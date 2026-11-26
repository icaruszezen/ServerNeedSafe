package updater

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"
)

// ParseSHA256SUMS parses standard sha256sum output (`<64-hex>  <filename>` or `<64-hex> *<filename>`).
func ParseSHA256SUMS(data []byte) (map[string]string, error) {
	sums := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		digest := strings.ToLower(strings.TrimSpace(fields[0]))
		if len(digest) != 64 {
			continue
		}
		if _, err := hex.DecodeString(digest); err != nil {
			continue
		}
		name := strings.TrimPrefix(strings.TrimSpace(fields[1]), "*")
		name = path.Base(strings.ReplaceAll(name, "\\", "/"))
		if name != "" && name != "." && name != "/" {
			sums[name] = digest
		}
	}
	if len(sums) == 0 {
		return nil, errors.New("SHA256SUMS.txt 内容无效或为空")
	}
	return sums, nil
}

// ChecksumVerification captures the verified expected SHA-256 hash and how trust was established.
type ChecksumVerification struct {
	SHA256        string   `json:"sha256"`
	TrustSource   string   `json:"trust_source"` // "official_github" | "cross_verified_mirrors" | "custom_mirror"
	VerifiedHosts []string `json:"verified_hosts"`
}

// FetchVerifiedChecksum retrieves SHA256SUMS.txt and establishes supply-chain trust:
//   - Prefer direct official GitHub whenever allowed (auto/direct).
//   - In auto mode, if direct official GitHub is unreachable, fetch SHA256SUMS.txt across distinct
//     China mirrors concurrently and require >= 2 independent mirror hosts to return the EXACT same hash
//     (and abort immediately on any hash disagreement).
//   - In custom mode, trust the user's explicitly configured custom mirror (still strictly verifying SHA-256).
func FetchVerifiedChecksum(
	ctx context.Context,
	client *http.Client,
	githubBaseURL string,
	repoSlug string,
	tagName string,
	assetName string,
	mirrorMode string,
	candidates []MirrorNode,
) (*ChecksumVerification, error) {
	if client == nil {
		client = newHTTPClient(10 * time.Second)
	}
	checksumCanonicalURL := fmt.Sprintf("%s/%s/releases/download/%s/SHA256SUMS.txt",
		strings.TrimRight(githubBaseURL, "/"),
		strings.Trim(repoSlug, "/"),
		tagName,
	)

	// Step 1: Try official GitHub direct first unless user locked to a custom mirror.
	if mirrorMode != "custom" {
		directNode := MirrorNode{ID: "direct", Name: "GitHub 官方直连", Prefix: "", Region: "global"}
		directTimeout := 10 * time.Second
		if mirrorMode == "auto" {
			directTimeout = 5 * time.Second
		}
		dCtx, cancel := context.WithTimeout(ctx, directTimeout)
		sums, err := fetchChecksumsViaMirror(dCtx, client, directNode, checksumCanonicalURL)
		cancel()
		if err == nil {
			digest, ok := sums[assetName]
			if !ok {
				return nil, fmt.Errorf("官方 SHA256SUMS.txt 中未找到目标产物 %s 的校验值，已拒绝更新", assetName)
			}
			return &ChecksumVerification{
				SHA256:        digest,
				TrustSource:   "official_github",
				VerifiedHosts: []string{"github.com"},
			}, nil
		}
		if mirrorMode == "direct" {
			return nil, fmt.Errorf("无法从 GitHub 官方获取 SHA256SUMS.txt（强制校验已中止更新）: %w", err)
		}
	}

	// Step 2: Custom single-mirror mode.
	if mirrorMode == "custom" {
		if len(candidates) == 0 {
			return nil, errors.New("未配置有效的自定义加速镜像")
		}
		cCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		sums, err := fetchChecksumsViaMirror(cCtx, client, candidates[0], checksumCanonicalURL)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("无法从自定义镜像获取 SHA256SUMS.txt（强制校验已中止更新）: %w", err)
		}
		digest, ok := sums[assetName]
		if !ok {
			return nil, fmt.Errorf("SHA256SUMS.txt 中缺少目标产物 %s 的校验值，已拒绝更新", assetName)
		}
		return &ChecksumVerification{
			SHA256:        digest,
			TrustSource:   "custom_mirror",
			VerifiedHosts: []string{MirrorHostKey(candidates[0])},
		}, nil
	}

	// Step 3: Auto mode fallback when direct GitHub is unreachable -> cross-verify across distinct mirrors.
	var mirrorNodes []MirrorNode
	seenHosts := make(map[string]struct{})
	for _, m := range candidates {
		if m.Prefix == "" {
			continue
		}
		host := MirrorHostKey(m)
		if _, dup := seenHosts[host]; dup {
			continue
		}
		seenHosts[host] = struct{}{}
		mirrorNodes = append(mirrorNodes, m)
	}
	if len(mirrorNodes) < 2 {
		return nil, errors.New("GitHub 官方直连不可达且可用独立镜像不足 2 个，无法完成 SHA256SUMS.txt 交叉校验（已拒绝更新）")
	}

	type mirrorSumResult struct {
		host   string
		name   string
		digest string
		err    error
	}
	resCh := make(chan mirrorSumResult, len(mirrorNodes))
	var wg sync.WaitGroup
	for _, m := range mirrorNodes {
		wg.Add(1)
		go func(node MirrorNode) {
			defer wg.Done()
			mCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			sums, err := fetchChecksumsViaMirror(mCtx, client, node, checksumCanonicalURL)
			if err != nil {
				resCh <- mirrorSumResult{host: MirrorHostKey(node), name: node.Name, err: err}
				return
			}
			digest, ok := sums[assetName]
			if !ok {
				resCh <- mirrorSumResult{host: MirrorHostKey(node), name: node.Name, err: fmt.Errorf("缺少产物 %s", assetName)}
				return
			}
			resCh <- mirrorSumResult{host: MirrorHostKey(node), name: node.Name, digest: digest}
		}(m)
	}
	wg.Wait()
	close(resCh)

	var agreedDigest string
	var verifiedHosts []string
	var errMsgs []string
	for r := range resCh {
		if r.err != nil {
			errMsgs = append(errMsgs, fmt.Sprintf("%s: %s", r.name, summarizeNetErr(r.err)))
			continue
		}
		if agreedDigest == "" {
			agreedDigest = r.digest
		} else if agreedDigest != r.digest {
			return nil, fmt.Errorf("安全告警：不同加速镜像返回的 %s SHA-256 校验值不一致（疑似镜像篡改或缓存异常），已立即中止更新", assetName)
		}
		verifiedHosts = append(verifiedHosts, r.host)
	}

	if len(verifiedHosts) < 2 {
		detail := ""
		if len(errMsgs) > 0 {
			detail = "（" + strings.Join(errMsgs, "; ") + "）"
		}
		return nil, fmt.Errorf("GitHub 官方直连不可达，且仅 %d 个独立镜像返回有效 SHA256SUMS.txt（至少需 2 个独立源交叉一致），已中止更新%s", len(verifiedHosts), detail)
	}

	return &ChecksumVerification{
		SHA256:        agreedDigest,
		TrustSource:   "cross_verified_mirrors",
		VerifiedHosts: verifiedHosts,
	}, nil
}

func fetchChecksumsViaMirror(ctx context.Context, client *http.Client, node MirrorNode, canonicalURL string) (map[string]string, error) {
	reqURL := BuildMirroredURL(node, canonicalURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", updaterUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, err
	}
	return ParseSHA256SUMS(raw)
}
