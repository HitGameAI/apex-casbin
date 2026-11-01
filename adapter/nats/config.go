/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\go-casbin-nats-adapter\config.go
 * @Description: NATS 适配器配置定义
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package natsadapter

import (
	"github.com/HitGameAI/apex-casbin/policy"
	"github.com/HitGameAI/apex-toolbox/pkg/logger"
)

// ChangeEvent NATS 适配器事件类型（与 policy.ChangeEvent 一致）
type ChangeEvent = policy.ChangeEvent

// WithNotifierLogger 设置通知器日志记录器
func WithNotifierLogger(l logger.ILogger) func(*NATSNotifier) {
	return func(nn *NATSNotifier) {
		if l != nil {
			nn.logger = l
		}
	}
}
