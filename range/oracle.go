package vrange

// 成功判据（oracle）求值：EXP 侧 success_oracle 与靶标侧 ground truth 共用
// 同一套语义——闸门要求两边口径一致，「EXP 自称成功」和「靶标确认真被打下来」
// 是两个独立判定。
//
// oracle JSON 形态（与 db.ExpAsset.success_oracle 同构）：
//   {"status_codes":[200], "keywords":["FLAG"], "regex":"CVE-\\d+"}
// 语义（声明的维度之间 AND，全部满足才算命中）：
//   - status_codes：响应状态码 ∈ 列表（未声明则不看）；
//   - keywords：所有关键字都在响应体中出现（子串、区分大小写；未声明则不看）；
//   - regex：Go regexp 命中响应体任意位置（未声明则不看）。
// 刻意从严：闸门语境下宁可误杀一条判据含糊的 EXP，也不放一条判据过松的
// （判据过松 = 打到任意页面都「成功」，EXP 库的命中率统计从此失真）。

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// oracleSpec 是 success_oracle 的结构化形态。
type oracleSpec struct {
	StatusCodes []int    `json:"status_codes"`
	Keywords    []string `json:"keywords"`
	Regex       string   `json:"regex"`

	re *regexp.Regexp `json:"-"`
}

// parseOracle 解析并预编译一条判据。空判据 / 非法 JSON / 非法正则都报错——
// 语义校验（db/service 层）挡的是「空」，这里连「写坏的正则」也挡。
func parseOracle(raw json.RawMessage) (*oracleSpec, error) {
	if len(raw) == 0 || string(raw) == "null" || strings.TrimSpace(string(raw)) == "{}" {
		return nil, fmt.Errorf("成功判据为空（没有判据就无法判定「拿下」）")
	}
	var o oracleSpec
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, fmt.Errorf("成功判据不是合法 JSON: %w", err)
	}
	if len(o.StatusCodes) == 0 && len(o.Keywords) == 0 && strings.TrimSpace(o.Regex) == "" {
		return nil, fmt.Errorf("成功判据需至少声明 status_codes / keywords / regex 之一")
	}
	if o.Regex != "" {
		re, err := regexp.Compile(o.Regex)
		if err != nil {
			return nil, fmt.Errorf("成功判据 regex 非法: %w", err)
		}
		o.re = re
	}
	return &o, nil
}

// evaluate 对一次响应求值：返回是否命中与第一条未满足的说明（全满足为空串）。
func (o *oracleSpec) evaluate(status int, body string) (bool, string) {
	if len(o.StatusCodes) > 0 {
		in := false
		for _, c := range o.StatusCodes {
			if status == c {
				in = true
				break
			}
		}
		if !in {
			return false, fmt.Sprintf("状态码 %d 不在 %v", status, o.StatusCodes)
		}
	}
	for _, kw := range o.Keywords {
		if !strings.Contains(body, kw) {
			return false, fmt.Sprintf("响应体缺少关键字 %q", kw)
		}
	}
	if o.re != nil && !o.re.MatchString(body) {
		return false, fmt.Sprintf("正则 %q 未命中响应体", o.Regex)
	}
	return true, ""
}
