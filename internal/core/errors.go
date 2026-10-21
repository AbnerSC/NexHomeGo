package core

import "fmt"

// 统一错误约定（等价 Java WebServer 的异常映射）：
//   - BadRequest      → HTTP 400，前端直接展示（对应 IllegalArgumentException）
//   - StatusError     → 指定 HTTP 状态码（401 未登录 / 404 未匹配等，对应 HttpResponseException）
//   - 其他 error      → HTTP 500，"操作失败: " + message（兜底）
// 三者响应体统一为 {ok:false, error:...}。

// BadRequest 业务校验错误（400）。
type BadRequest struct{ msg string }

func (e *BadRequest) Error() string { return e.msg }

// NewBadRequest 构造 400 参数/校验错误。
func NewBadRequest(format string, args ...interface{}) error {
	if len(args) == 0 {
		return &BadRequest{msg: format}
	}
	return &BadRequest{msg: fmt.Sprintf(format, args...)}
}

// StatusError 带 HTTP 状态码的响应错误。
type StatusError struct {
	Code int
	Msg  string
}

func (e *StatusError) Error() string { return e.Msg }

// Unauthorized 401（未登录或登录过期）。
func Unauthorized(msg string) error { return &StatusError{Code: 401, Msg: msg} }

// NotFound 404。
func NotFound(msg string) error { return &StatusError{Code: 404, Msg: msg} }
