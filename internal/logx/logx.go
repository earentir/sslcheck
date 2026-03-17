// Package logx provides dual-sink structured logging (stderr + optional file).
package logx

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	mu       sync.Mutex
	stderrL  *slog.Logger
	fileL    *slog.Logger
	fileOut  *os.File
	levelStr string
	filePath string // resolved path or "-" or "(none)"
)

func init() {
	stderrL = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.Level(100)}))
}

// Init configures logging from CLI flags.
// Rules:
//   - --log-file only → file at info, stderr at info
//   - --log-level only → file sslcheck.log next to executable, stderr at that level
//   - both → file at path, both at level
//   - neither → stderr warn only, no file
func Init(logFileFlag, logLevelFlag string) (banner string, err error) {
	mu.Lock()
	defer mu.Unlock()

	if fileOut != nil {
		_ = fileOut.Close()
		fileOut = nil
		fileL = nil
	}

	var consoleLevel, fileLevel slog.Level
	hasFile := strings.TrimSpace(logFileFlag) != ""
	hasLevel := strings.TrimSpace(logLevelFlag) != ""

	switch {
	case hasFile && hasLevel:
		filePath = strings.TrimSpace(logFileFlag)
		consoleLevel = parseLevel(logLevelFlag)
		fileLevel = consoleLevel
		levelStr = strings.ToLower(strings.TrimSpace(logLevelFlag))
	case hasFile && !hasLevel:
		filePath = strings.TrimSpace(logFileFlag)
		consoleLevel = slog.LevelInfo
		fileLevel = slog.LevelInfo
		levelStr = "info"
	case !hasFile && hasLevel:
		levelStr = strings.ToLower(strings.TrimSpace(logLevelFlag))
		consoleLevel = parseLevel(logLevelFlag)
		fileLevel = consoleLevel
		exe, exErr := os.Executable()
		if exErr != nil {
			filePath = filepath.Join(".", "sslcheck.log")
		} else {
			filePath = filepath.Join(filepath.Dir(exe), "sslcheck.log")
		}
	default:
		consoleLevel = slog.LevelWarn
		fileLevel = slog.LevelInfo
		levelStr = "warn"
		filePath = ""
	}

	optsConsole := &slog.HandlerOptions{
		Level:     consoleLevel,
		AddSource: consoleLevel <= slog.LevelDebug,
	}
	optsFile := &slog.HandlerOptions{
		Level:     fileLevel,
		AddSource: true,
	}

	stderrL = slog.New(slog.NewTextHandler(os.Stderr, optsConsole))

	if filePath != "" && filePath != "-" {
		f, openErr := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if openErr != nil && !hasFile {
			// --log-level only: retry next to cwd if binary dir is not writable
			alt := filepath.Join(".", "sslcheck.log")
			f, openErr = os.OpenFile(alt, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			if openErr == nil {
				filePath = alt
			}
		}
		if openErr != nil {
			Warn("log file open failed, stderr only", "path", filePath, "err", openErr.Error())
			filePath = "(file failed: " + openErr.Error() + ")"
		} else {
			fileOut = f
			fileL = slog.New(slog.NewTextHandler(f, optsFile))
		}
	}

	fileDesc := filePath
	if fileDesc == "" {
		fileDesc = "(none)"
	} else if fileL == nil && hasFile && !strings.HasPrefix(fileDesc, "(") {
		fileDesc = filePath
	}
	banner = fmt.Sprintf("sslcheck logging: level=%s console=stderr file=%s", levelStr, fileDesc)
	return banner, nil
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func emit(level slog.Level, msg string, args ...any) {
	ctx := context.Background()
	if stderrL.Enabled(ctx, level) {
		stderrL.Log(ctx, level, msg, args...)
	}
	if fileL != nil && fileL.Enabled(ctx, level) {
		fileL.Log(ctx, level, msg, args...)
	}
}

// Debug logs at debug level.
func Debug(msg string, args ...any) { emit(slog.LevelDebug, msg, args...) }

// Info logs at info level.
func Info(msg string, args ...any) { emit(slog.LevelInfo, msg, args...) }

// Warn logs at warn level.
func Warn(msg string, args ...any) { emit(slog.LevelWarn, msg, args...) }

// Error logs at error level.
func Error(msg string, args ...any) { emit(slog.LevelError, msg, args...) }

// Sync flushes the log file if any.
func Sync() {
	mu.Lock()
	defer mu.Unlock()
	if fileOut != nil {
		_ = fileOut.Sync()
	}
}

// LevelString returns the configured level name for display.
func LevelString() string { return levelStr }
