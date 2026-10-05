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

var appVersion = sourceVersion()

const (
    appName = "StreamScout Downloader"
    pythonVersion = "3.12.10"
    createNoWindow = 0x08000000
)

func sourceVersion() string {
    re := regexp.MustCompile(`APP_VERSION\s*=\s*["\']([^"\']+)["\']`)
    if m := re.FindSubmatch(appSource); len(m) > 1 { return string(m[1]) }
    return "0.0.0"
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
    f, err := os.Create(tmp); if err != nil { return err }
    _, cpErr := io.Copy(f, resp.Body)
    closeErr := f.Close()
    if cpErr != nil { return cpErr }; if closeErr != nil { return closeErr }
    return os.Rename(tmp, dest)
}

func findPython(appDir string) string {
    candidates := []string{
        filepath.Join(appDir, "python", "pythonw.exe"),
        filepath.Join(appDir, "python", "python.exe"),
    }
    for _, p := range candidates { if st, err := os.Stat(p); err == nil && st.Size() > 0 { return p } }
    for _, name := range []string{"pythonw.exe", "python.exe", "py.exe"} {
        if p, err := exec.LookPath(name); err == nil { return p }
    }
    return ""
}

func installPython(appDir string) (string, error) {
    pyDir := filepath.Join(appDir, "python")
    installer := filepath.Join(appDir, "bootstrap", "python-"+pythonVersion+"-amd64.exe")
    if _, err := os.Stat(installer); err != nil {
        url := "https://www.python.org/ftp/python/"+pythonVersion+"/python-"+pythonVersion+"-amd64.exe"
        logLine(appDir, "Python installer download: "+url)
        if err := download(url, installer); err != nil { return "", fmt.Errorf("Python 다운로드 실패: %w", err) }
    }
    args := []string{"/quiet", "InstallAllUsers=0", "PrependPath=0", "Include_test=0", "Include_launcher=0", "Include_tcltk=1", "Include_pip=1", "TargetDir="+pyDir}
    cmd := exec.Command(installer, args...); hidden(cmd)
    logLine(appDir, "Python silent install start")
    if out, err := cmd.CombinedOutput(); err != nil { return "", fmt.Errorf("Python 설치 실패: %w (%s)", err, strings.TrimSpace(string(out))) }
    p := filepath.Join(pyDir, "pythonw.exe")
    if _, err := os.Stat(p); err != nil { p = filepath.Join(pyDir, "python.exe") }
    if _, err := os.Stat(p); err != nil { return "", fmt.Errorf("Python 설치 후 실행 파일을 찾을 수 없습니다") }
    logLine(appDir, "Python silent install complete")
    return p, nil
}

func consolePython(py string) string {
    base := strings.ToLower(filepath.Base(py))
    if base == "pythonw.exe" {
        p := filepath.Join(filepath.Dir(py), "python.exe")
        if _, err := os.Stat(p); err == nil { return p }
    }
    return py
}

func ensureDeps(appDir, py string) error {
    marker := filepath.Join(appDir, "bootstrap", "deps-v242.ok")
    if _, err := os.Stat(marker); err == nil { return nil }
    cpy := consolePython(py)
    cmds := [][]string{
        {"-m", "ensurepip", "--upgrade"},
        {"-m", "pip", "install", "--disable-pip-version-check", "--no-warn-script-location", "--upgrade", "requests>=2.31", "yt-dlp>=2025.1.0", "playwright>=1.50", "Pillow>=10.4", "imageio-ffmpeg>=0.5"},
    }
    for i, a := range cmds {
        cmd := exec.Command(cpy, a...); hidden(cmd)
        logLine(appDir, fmt.Sprintf("dependency step %d start", i+1))
        out, err := cmd.CombinedOutput()
        if err != nil {
            if i == 0 { continue }
            return fmt.Errorf("필수 구성요소 설치 실패: %w (%s)", err, strings.TrimSpace(string(out)))
        }
    }
    if err := os.MkdirAll(filepath.Dir(marker), 0755); err != nil { return err }
    return os.WriteFile(marker, []byte(appVersion+"\n"), 0644)
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
    if err := writeIfChanged(script, appSource); err != nil { messageBox("프로그램 파일 준비 실패: "+err.Error()); return }
    _ = writeIfChanged(icon, appIcon)

    py := findPython(appDir)
    if py == "" {
        var err error
        py, err = installPython(appDir)
        if err != nil { logLine(appDir, err.Error()); messageBox(err.Error()); return }
    }
    if err := ensureDeps(appDir, py); err != nil { logLine(appDir, err.Error()); messageBox(err.Error()); return }

    args := []string{script}
    args = append(args, os.Args[1:]...)
    cmd := exec.Command(py, args...)
    cmd.Dir = appDir
    cmd.Env = append(os.Environ(), "PYTHONUTF8=1", "PYTHONIOENCODING=utf-8")
    hidden(cmd)
    if err := cmd.Start(); err != nil { logLine(appDir, err.Error()); messageBox("StreamScout 실행 실패: "+err.Error()); return }

    h := sha256.Sum256(appSource)
    logLine(appDir, "launched v"+appVersion+" source="+hex.EncodeToString(h[:8]))
}
