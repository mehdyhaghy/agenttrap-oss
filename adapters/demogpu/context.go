package demogpu

import "context"

func withInfo(ctx context.Context, info *reqInfo) context.Context {
	return context.WithValue(ctx, ctxKey{}, info)
}

func infoFrom(ctx context.Context) *reqInfo {
	if info, ok := ctx.Value(ctxKey{}).(*reqInfo); ok {
		return info
	}
	return &reqInfo{}
}
