//go:build windows

package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

//go:embed payload/stream_scout.py
var appSource []byte

//go:embed payload/stream_scout.ico
var appIcon []byte

//go:embed VERSION
var versionBytes []byte

var appVersion = strings.TrimSpace(string(versionBytes))

const (
	appName        = "StreamScout Downloader"
	pythonVersion  = "3.12.10"
	createNoWindow = 0x08000000
)

func effectiveSource() []byte {
	re := regexp.MustCompile(`APP_VERSION\s*=\s*["\']([^"\']+)["\']`)
	repl := []byte(`APP_VERSION = "` + appVersion + `"`)
	return re.ReplaceAll(appSource, repl)
}

func localAppDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		if home, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(home, "AppData", "Local")
		}
	}
	return filepath.Join(base, "StreamScoutDownloader")
}

func logLine(appDir, s string) {
	_ = os.MkdirAll(appDir, 0755)
	f, err := os.OpenFile(filepath.Join(appDir, "bootstrap.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\r\n", time.Now().Format("2006-01-02 15:04:05"), s)
}

func hidden(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}

func writeIfChanged(path string, data []byte) error {
	want := sha256.Sum256(data)
	if b, err := os.ReadFile(path); err == nil {
		got := sha256.Sum256(b)
		if got == want {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	_ = os.Remove(path)
	return os.Rename(tmp, path)
}

func download(url, dest string) error {
	client := &http.Client{Timeout: 20 * time.Minute}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "StreamScoutDownloader/"+appVersion)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	tmp := dest + ".download"
	_ = os.Remove(tmp)
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	n, cpErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if cpErr != nil {
		return cpErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n < 1024*1024 {
		return fmt.Errorf("downloaded file is unexpectedly small (%d bytes)", n)
	}
	_ = os.Remove(dest)
	return os.Rename(tmp, dest)
}

func managedPython(appDir string) string {
	candidates := []string{
		filepath.Join(appDir, "python", "pythonw.exe"),
		filepath.Join(appDir, "python", "python.exe"),
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			return p
		}
	}
	return ""
}

func managedVenvPython(appDir string) string {
	candidates := []string{
		filepath.Join(appDir, "pyenv", "Scripts", "pythonw.exe"),
		filepath.Join(appDir, "pyenv", "Scripts", "python.exe"),
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			return p
		}
	}
	return ""
}

func consolePython(py string) string {
	base := strings.ToLower(filepath.Base(py))
	if base == "pythonw.exe" {
		p := filepath.Join(filepath.Dir(py), "python.exe")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return py
}

func validatePython(py string) error {
	if py == "" {
		return fmt.Errorf("Python 실행 파일 없음")
	}
	cpy := consolePython(py)
	cmd := exec.Command(cpy, "-c", "import sys, tkinter; assert sys.version_info >= (3, 11); print(sys.executable); print(sys.version)")
	hidden(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Python 검증 실패: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func uniqueExisting(candidates []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, p := range candidates {
		p = strings.TrimSpace(strings.Trim(p, `"`))
		if p == "" {
			continue
		}
		key := strings.ToLower(p)
		if seen[key] {
			continue
		}
		seen[key] = true
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Size() > 0 {
			out = append(out, p)
		}
	}
	return out
}

func pythonPathsFromOutput(out string) []string {
	// Accept output from py -0p, reg query, and where.exe.
	re := regexp.MustCompile(`(?i)[A-Z]:\\[^\r\n"]*?pythonw?\.exe`)
	return re.FindAllString(out, -1)
}

func findUsableSystemPython(appDir string) string {
	candidates := []string{}
	local := os.Getenv("LOCALAPPDATA")
	pf := os.Getenv("ProgramFiles")
	pf86 := os.Getenv("ProgramFiles(x86)")
	for _, ver := range []string{"314", "313", "312", "311"} {
		if local != "" {
			candidates = append(candidates, filepath.Join(local, "Programs", "Python", "Python"+ver, "python.exe"))
		}
		if pf != "" {
			candidates = append(candidates, filepath.Join(pf, "Python"+ver, "python.exe"))
		}
		if pf86 != "" {
			candidates = append(candidates, filepath.Join(pf86, "Python"+ver, "python.exe"))
		}
	}

	probes := [][]string{
		{"py.exe", "-0p"},
		{"reg.exe", "query", `HKCU\Software\Python\PythonCore`, "/s", "/v", "ExecutablePath"},
		{"reg.exe", "query", `HKLM\Software\Python\PythonCore`, "/s", "/v", "ExecutablePath"},
		{"where.exe", "python.exe"},
	}
	for _, a := range probes {
		cmd := exec.Command(a[0], a[1:]...)
		hidden(cmd)
		out, err := cmd.CombinedOutput()
		if err == nil || len(out) > 0 {
			candidates = append(candidates, pythonPathsFromOutput(string(out))...)
		}
	}

	for _, p := range uniqueExisting(candidates) {
		// Never recursively use our broken/incomplete managed folders as a "system" fallback.
		low := strings.ToLower(p)
		if strings.Contains(low, strings.ToLower(filepath.Join(appDir, "python"))) || strings.Contains(low, strings.ToLower(filepath.Join(appDir, "pyenv"))) {
			continue
		}
		if err := validatePython(p); err == nil {
			logLine(appDir, "usable installed Python found: "+p)
			return p
		} else {
			logLine(appDir, "installed Python rejected: "+p+" : "+err.Error())
		}
	}
	return ""
}

func createPrivateVenv(appDir, basePy string) (string, error) {
	if basePy == "" {
		return "", fmt.Errorf("기반 Python 실행 파일이 없습니다")
	}
	venvDir := filepath.Join(appDir, "pyenv")
	if py := managedVenvPython(appDir); py != "" {
		if err := validatePython(py); err == nil {
			return py, nil
		}
	}

	_ = os.RemoveAll(venvDir)
	cpy := consolePython(basePy)
	cmd := exec.Command(cpy, "-m", "venv", "--copies", venvDir)
	hidden(cmd)
	logLine(appDir, "create private venv from: "+cpy)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		logLine(appDir, "venv output: "+strings.TrimSpace(string(out)))
	}
	if err != nil {
		return "", fmt.Errorf("StreamScout 전용 Python 환경 생성 실패: %w", err)
	}
	py := managedVenvPython(appDir)
	if err := validatePython(py); err != nil {
		return "", fmt.Errorf("전용 Python 환경 검증 실패: %w", err)
	}
	logLine(appDir, "private venv ready: "+py)
	return py, nil
}

func installPython(appDir string) (string, error) {
	pyDir := filepath.Join(appDir, "python")
	installer := filepath.Join(appDir, "bootstrap", "python-"+pythonVersion+"-amd64.exe")
	needDownload := true
	if st, err := os.Stat(installer); err == nil && st.Size() > 10*1024*1024 {
		needDownload = false
	}
	if needDownload {
		_ = os.Remove(installer)
		url := "https://www.python.org/ftp/python/" + pythonVersion + "/python-" + pythonVersion + "-amd64.exe"
		logLine(appDir, "Python installer download: "+url)
		if err := download(url, installer); err != nil {
			return "", fmt.Errorf("Python 다운로드 실패: %w", err)
		}
	}

	runInstall := func() error {
		args := []string{"/quiet", "InstallAllUsers=0", "PrependPath=0", "Include_exe=1", "Include_test=0", "Include_launcher=0", "Include_tcltk=1", "Include_pip=1", "AssociateFiles=0", "Shortcuts=0", "TargetDir=" + pyDir}
		cmd := exec.Command(installer, args...)
		hidden(cmd)
		logLine(appDir, "Python private silent install start target="+pyDir)
		out, err := cmd.CombinedOutput()
		if len(out) > 0 {
			logLine(appDir, "Python installer output: "+strings.TrimSpace(string(out)))
		}
		if err != nil {
			return fmt.Errorf("Python 설치 실패: %w", err)
		}
		return nil
	}

	firstErr := runInstall()
	py := managedPython(appDir)
	if firstErr == nil && py != "" {
		if err := validatePython(py); err == nil {
			logLine(appDir, "Python private install complete: "+py)
			return py, nil
		}
	}

	// A same-version Python already installed elsewhere can make the installer enter
	// maintenance mode and return success without creating TargetDir. Retry once with
	// a fresh installer, then allow caller to discover that existing installation.
	if firstErr != nil {
		logLine(appDir, "Python install first attempt failed: "+firstErr.Error())
	}
	if py == "" {
		logLine(appDir, "Python installer finished but TargetDir has no python.exe")
	}
	_ = os.Remove(installer)
	url := "https://www.python.org/ftp/python/" + pythonVersion + "/python-" + pythonVersion + "-amd64.exe"
	if derr := download(url, installer); derr == nil {
		if err2 := runInstall(); err2 != nil {
			logLine(appDir, "Python install retry failed: "+err2.Error())
		}
	} else {
		logLine(appDir, "Python installer re-download failed: "+derr.Error())
	}

	py = managedPython(appDir)
	if py != "" {
		if err := validatePython(py); err == nil {
			return py, nil
		}
	}
	return "", fmt.Errorf("StreamScout 전용 폴더에 Python 실행 파일을 만들지 못했습니다")
}

func selectRuntime(appDir string) (string, error) {
	// 1) Reuse our isolated venv when healthy.
	if py := managedVenvPython(appDir); py != "" {
		if err := validatePython(py); err == nil {
			return py, nil
		}
		logLine(appDir, "existing venv invalid; rebuilding")
		_ = os.RemoveAll(filepath.Join(appDir, "pyenv"))
	}

	// 2) Reuse private full Python if present and create the isolated venv from it.
	if base := managedPython(appDir); base != "" {
		if err := validatePython(base); err == nil {
			if py, err := createPrivateVenv(appDir, base); err == nil {
				return py, nil
			} else {
				logLine(appDir, err.Error())
			}
		}
	}

	// 3) Try installing our private full Python.
	if base, err := installPython(appDir); err == nil {
		if py, verr := createPrivateVenv(appDir, base); verr == nil {
			return py, nil
		} else {
			logLine(appDir, verr.Error())
		}
	} else {
		logLine(appDir, "private Python install did not materialize: "+err.Error())
	}

	// 4) Same-version installer may have redirected to an already installed Python.
	// Find a real Python 3.11+ with Tk, then create a StreamScout-only venv from it.
	if base := findUsableSystemPython(appDir); base != "" {
		if py, err := createPrivateVenv(appDir, base); err == nil {
			return py, nil
		} else {
			logLine(appDir, err.Error())
		}
	}

	return "", fmt.Errorf("사용 가능한 Python 3.11 이상 실행 파일을 찾지 못했습니다.\n\n로그: %s", filepath.Join(appDir, "bootstrap.log"))
}

func runDepStep(appDir, cpy string, label string, args ...string) error {
	cmd := exec.Command(cpy, args...)
	hidden(cmd)
	cmd.Env = append(os.Environ(),
		"PYTHONUTF8=1", "PYTHONIOENCODING=utf-8", "PYTHONNOUSERSITE=1",
		"PIP_DISABLE_PIP_VERSION_CHECK=1", "PIP_NO_INPUT=1")
	logLine(appDir, "dependency "+label+" start")
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		logLine(appDir, "dependency "+label+" output: "+strings.TrimSpace(string(out)))
	}
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	logLine(appDir, "dependency "+label+" complete")
	return nil
}

func ensureDeps(appDir, py string) []string {
	marker := filepath.Join(appDir, "bootstrap", "deps-v244.ok")
	if _, err := os.Stat(marker); err == nil {
		return nil
	}
	cpy := consolePython(py)
	warnings := []string{}

	// Never use another Python installation. Everything is installed into StreamScout's private Python.
	_ = runDepStep(appDir, cpy, "ensurepip", "-m", "ensurepip", "--upgrade")
	if err := runDepStep(appDir, cpy, "pip-bootstrap", "-m", "pip", "install", "--retries", "5", "--timeout", "60", "--no-warn-script-location", "--upgrade", "pip", "setuptools", "wheel"); err != nil {
		warnings = append(warnings, err.Error())
	}

	packages := []struct{ name, spec string }{
		{"requests", "requests>=2.31"},
		{"yt-dlp", "yt-dlp>=2025.1.0"},
		{"playwright", "playwright>=1.50"},
		{"Pillow", "Pillow>=10.4"},
		{"imageio-ffmpeg", "imageio-ffmpeg>=0.5"},
	}
	failed := false
	for _, pkg := range packages {
		args := []string{"-m", "pip", "install", "--retries", "5", "--timeout", "60", "--prefer-binary", "--no-warn-script-location", "--upgrade", pkg.spec}
		if err := runDepStep(appDir, cpy, pkg.name, args...); err != nil {
			failed = true
			warnings = append(warnings, pkg.name+" 설치 실패: "+err.Error())
		}
	}

	// Verify imports. A failed optional package must not prevent the UI itself from opening.
	verify := []struct{ name, mod string }{
		{"requests", "requests"}, {"yt-dlp", "yt_dlp"}, {"playwright", "playwright"},
		{"Pillow", "PIL"}, {"imageio-ffmpeg", "imageio_ffmpeg"},
	}
	for _, v := range verify {
		if err := runDepStep(appDir, cpy, "verify-"+v.name, "-c", "import "+v.mod+"; print('ok')"); err != nil {
			failed = true
			warnings = append(warnings, v.name+" 확인 실패")
		}
	}

	if !failed {
		if err := os.MkdirAll(filepath.Dir(marker), 0755); err == nil {
			_ = os.WriteFile(marker, []byte(appVersion+"\n"), 0644)
		}
	} else {
		logLine(appDir, "some optional dependencies failed; UI launch will continue")
	}
	return warnings
}

func messageBox(text string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	proc := user32.NewProc("MessageBoxW")
	t, _ := syscall.UTF16PtrFromString(text)
	c, _ := syscall.UTF16PtrFromString(appName)
	proc.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), 0x10)
}

func main() {
	appDir := localAppDir()
	if err := os.MkdirAll(appDir, 0755); err != nil {
		messageBox(err.Error())
		return
	}
	script := filepath.Join(appDir, "stream_scout.py")
	icon := filepath.Join(appDir, "stream_scout.ico")
	source := effectiveSource()
	if err := writeIfChanged(script, source); err != nil {
		messageBox("프로그램 파일 준비 실패: " + err.Error())
		return
	}
	_ = writeIfChanged(icon, appIcon)

	// v2.4.4+: prefer a StreamScout-isolated venv. If the Python installer detects
	// an existing same-version Python and does not populate TargetDir, locate that
	// valid runtime and use it only as the base for our private venv.
	py, runtimeErr := selectRuntime(appDir)
	if runtimeErr != nil {
		logLine(appDir, runtimeErr.Error())
		messageBox(runtimeErr.Error())
		return
	}

	warnings := ensureDeps(appDir, py)
	if len(warnings) > 0 {
		logLine(appDir, "dependency warnings: "+strings.Join(warnings, " | "))
		// Do not abort: the application can start and most missing optional components
		// can be repaired on a later run. Exact details remain in bootstrap.log.
	}

	args := []string{script}
	args = append(args, os.Args[1:]...)
	cmd := exec.Command(py, args...)
	cmd.Dir = appDir
	cmd.Env = append(os.Environ(), "PYTHONUTF8=1", "PYTHONIOENCODING=utf-8", "PYTHONNOUSERSITE=1")
	hidden(cmd)
	if err := cmd.Start(); err != nil {
		logLine(appDir, err.Error())
		messageBox("StreamScout 실행 실패: " + err.Error())
		return
	}

	h := sha256.Sum256(source)
	logLine(appDir, "launched v"+appVersion+" source="+hex.EncodeToString(h[:8]))
}
