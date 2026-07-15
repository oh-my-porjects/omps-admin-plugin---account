package main

import (
	"os"
	"strings"
	"testing"
)

func TestAdminIntentsUseV4DialogProtocol(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("admin-intents.yaml")
	if err != nil {
		t.Fatalf("读取 admin-intents.yaml: %v", err)
	}
	text := string(raw)

	for _, forbidden := range []string{
		"type: navigate",
		"type: open-drawer",
		"target_page_key:",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("admin-intents.yaml 仍包含被禁用协议 %q", forbidden)
		}
	}
	for _, line := range strings.Split(text, "\\n") {
		if strings.HasPrefix(line, "    template: { id: standard-detail") ||
			strings.HasPrefix(line, "    template: { id: standard-form") {
			t.Fatalf("admin-intents.yaml 仍包含独立操作页或详情页 %q", line)
		}
	}

	if got := strings.Count(text, "\n    route:"); got != 1 {
		t.Fatalf("可导航页面数量 = %d，期望 1", got)
	}
	if got := strings.Count(text, "type: open-dialog"); got < 4 {
		t.Fatalf("open-dialog 声明数量 = %d，期望至少 4", got)
	}

	for _, pageKey := range []string{
		"account.list",
	} {
		if !strings.Contains(text, "  - key: "+pageKey+"\n") {
			t.Errorf("缺少可导航页面 %s", pageKey)
		}
	}
	for _, actionKey := range []string{
		"account.list.action.open_role",
		"account.list.action.create",
		"account.list.action.detail",
		"account.list.action.edit",
		"account.list.action.reset_password",
	} {
		if !strings.Contains(text, "      - key: "+actionKey+"\n") {
			t.Errorf("缺少弹窗动作 %s", actionKey)
		}
	}
}
