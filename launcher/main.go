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
    appName = "StreamScout Downloader"
    pythonVersion = "3.12.10"
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
        if home, err := os.UserHomeDir(); err == nil { base = filepath.Join(home, "AppData", "Local") }
    }
    return filepath.Join(base, "StreamScoutDownloader")
}

func logLine(appDir, s string) {
    _ = os.MkdirAll(appDir, 0755)
    f, err := os.OpenFile(filepath.Join(appDir, "bootstrap.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
    if err != nil { return }
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
        if got == want { return nil }
    }
    if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { return err }
    tmp := path + ".tmp"
    if err := os.WriteFile(tmp, data, 0644); err != nil { return err }
    _ = os.Remove(path)
    return os.Rename(tmp, path)
}

func download(url, dest string) error {
    client := &http.Client{Timeout: 20 * time.Minute}
    req, _ := http.NewRequest("GET", url, nil)
    req.Header.Set("User-Agent", "StreamScoutDownloader/"+appVersion)
    resp, err := client.Do(req)
    if err != nil { return err }
    defer resp.Body.Close()
    if resp.StatusCode < 200 || resp.StatusCode >= 300 { return fmt.Errorf("HTTP %s", resp.Status) }
    if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil { return err }
    tmp := dest + ".download"
    _ = os.Remove(tmp)
    f, err := os.Create(tmp); if err != nil { return err }
    n, cpErr := io.Copy(f, resp.Body)
    closeErr := f.Close()
    if cpErr != nil { return cpErr }; if closeErr != nil { return closeErr }
    if n < 1024*1024 { return fmt.Errorf("downloaded file is unexpectedly small (%d bytes)", n) }
    _ = os.Remove(dest)
    return os.Rename(tmp, dest)
}

func managedPython(appDir string) string {
    candidates := []string{
        filepath.Join(appDir, "python", "pythonw.exe"),
        filepath.Join(appDir, "python", "python.exe"),
    }
    for _, p := range candidates {
        if st, err := os.Stat(p); err == nil && st.Size() > 0 { return p }
    }
    return ""
}

func consolePython(py string) string {
    base := strings.ToLower(filepath.Base(py))
    if base == "pythonw.exe" {
        p := filepath.Join(filepath.Dir(py), "python.exe")
        if _, err := os.Stat(p); err == nil { return p }
    }
    return py
}

func validatePython(py string) error {
    if py == "" { return fmt.Errorf("Python 실행 파일 없음") }
    cpy := consolePython(py)
    cmd := exec.Command(cpy, "-c", "import sys, tkinter; assert sys.version_info >= (3, 11); print(sys.version)")
    hidden(cmd)
    out, err := cmd.CombinedOutput()
    if err != nil { return fmt.Errorf("Python 검증 실패: %w (%s)", err, strings.TrimSpace(string(out))) }
    return nil
}

func installPython(appDir string) (string, error) {
    pyDir := filepath.Join(appDir, "python")
    installer := filepath.Join(appDir, "bootstrap", "python-"+pythonVersion+"-amd64.exe")
    needDownload := true
    if st, err := os.Stat(installer); err == nil && st.Size() > 10*1024*1024 { needDownload = false }
    if needDownload {
        _ = os.Remove(installer)
        url := "https://www.python.org/ftp/python/"+pythonVersion+"/python-"+pythonVersion+"-amd64.exe"
        logLine(appDir, "Python installer download: "+url)
        if err := download(url, installer); err != nil { return "", fmt.Errorf("Python 다운로드 실패: %w", err) }
    }

    runInstall := func() error {
        args := []string{"/quiet", "InstallAllUsers=0", "PrependPath=0", "Include_test=0", "Include_launcher=0", "Include_tcltk=1", "Include_pip=1", "Shortcuts=0", "TargetDir="+pyDir}
        cmd := exec.Command(installer, args...); hidden(cmd)
        logLine(appDir, "Python private silent install start")
        out, err := cmd.CombinedOutput()
        if err != nil { return fmt.Errorf("Python 설치 실패: %w (%s)", err, strings.TrimSpace(string(out))) }
        return nil
    }

    if err := runInstall(); err != nil {
        logLine(appDir, "Python install first attempt failed: "+err.Error())
        _ = os.Remove(installer)
        url := "https://www.python.org/ftp/python/"+pythonVersion+"/python-"+pythonVersion+"-amd64.exe"
        if derr := download(url, installer); derr != nil { return "", fmt.Errorf("Python 재다운로드 실패: %w", derr) }
        if err2 := runInstall(); err2 != nil { return "", err2 }
    }

    py := managedPython(appDir)
    if err := validatePython(py); err != nil { return "", err }
    logLine(appDir, "Python private install complete")
    return py, nil
}

func runDepStep(appDir, cpy string, label string, args ...string) error {
    cmd := exec.Command(cpy, args...)
    hidden(cmd)
    cmd.Env = append(os.Environ(),
        "PYTHONUTF8=1", "PYTHONIOENCODING=utf-8", "PYTHONNOUSERSITE=1",
        "PIP_DISABLE_PIP_VERSION_CHECK=1", "PIP_NO_INPUT=1")
    logLine(appDir, "dependency "+label+" start")
    out, err := cmd.CombinedOutput()
    if len(out) > 0 { logLine(appDir, "dependency "+label+" output: "+strings.TrimSpace(string(out))) }
    if err != nil { return fmt.Errorf("%s: %w", label, err) }
    logLine(appDir, "dependency "+label+" complete")
    return nil
}

func ensureDeps(appDir, py string) []string {
    marker := filepath.Join(appDir, "bootstrap", "deps-v243.ok")
    if _, err := os.Stat(marker); err == nil { return nil }
    cpy := consolePython(py)
    warnings := []string{}

    _ = runDepStep(appDir, cpy, "ensurepip", "-m", "ensurepip", "--upgrade")
    if err := runDepStep(appDir, cpy, "pip-bootstrap", "-m", "pip", "install", "--retries", "5", "--timeout", "60", "--no-warn-script-location", "--upgrade", "pip", "setuptools", "wheel"); err != nil {
        warnings = append(warnings, err.Error())
    }

    packages := []struct{name, spec string}{
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

    verify := []struct{name, mod string}{
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
    if err := os.MkdirAll(appDir, 0755); err != nil { messageBox(err.Error()); return }
    script := filepath.Join(appDir, "stream_scout.py")
    icon := filepath.Join(appDir, "stream_scout.ico")
    source := effectiveSource()
    if err := writeIfChanged(script, source); err != nil { messageBox("프로그램 파일 준비 실패: "+err.Error()); return }
    _ = writeIfChanged(icon, appIcon)

    py := managedPython(appDir)
    if err := validatePython(py); err != nil {
        logLine(appDir, "managed Python unavailable/invalid: "+err.Error())
        var installErr error
        py, installErr = installPython(appDir)
        if installErr != nil { logLine(appDir, installErr.Error()); messageBox(installErr.Error()+"\n\n로그: "+filepath.Join(appDir, "bootstrap.log")); return }
    }

    warnings := ensureDeps(appDir, py)
    if len(warnings) > 0 {
        logLine(appDir, "dependency warnings: "+strings.Join(warnings, " | "))
    }

    args := []string{script}
    args = append(args, os.Args[1:]...)
    cmd := exec.Command(py, args...)
    cmd.Dir = appDir
    cmd.Env = append(os.Environ(), "PYTHONUTF8=1", "PYTHONIOENCODING=utf-8", "PYTHONNOUSERSITE=1")
    hidden(cmd)
    if err := cmd.Start(); err != nil { logLine(appDir, err.Error()); messageBox("StreamScout 실행 실패: "+err.Error()); return }

    h := sha256.Sum256(source)
    logLine(appDir, "launched v"+appVersion+" source="+hex.EncodeToString(h[:8]))
}
