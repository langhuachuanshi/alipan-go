package file

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/langhuachuanshi/alipan-go/alipan/invoker"
	"github.com/langhuachuanshi/alipan-go/alipan/types"
)

// UploadRequest 上传请求。
type UploadRequest struct {
	FilePath      string
	ParentFileID  string
	DriveID       string
	Name          string
	CheckNameMode types.CheckNameMode
	OnProgress    func(sent, total int64)
}

type createFileResp struct {
	FileID       string                 `json:"file_id"`
	UploadID     string                 `json:"upload_id"`
	DriveID      string                 `json:"drive_id"`
	ParentFileID string                 `json:"parent_file_id"`
	DomainID     string                 `json:"domain_id"`
	PartInfoList []types.UploadPartInfo `json:"part_info_list"`
	RapidUpload  bool                   `json:"rapid_upload"`
	Exist        bool                   `json:"exist"`
	Status       string                 `json:"status"`
	Code         string                 `json:"code"`
	Message      string                 `json:"message"`
	PreHash      string                 `json:"pre_hash"`
	RevisionID   string                 `json:"revision_id"`
	Location     string                 `json:"location"`
}

// Upload 上传文件（含秒传、分片、续期）。
func (s *Service) Upload(ctx context.Context, req *UploadRequest) (*types.BaseFile, error) {
	if req == nil || req.FilePath == "" {
		return nil, invoker.NewAPIError(0, "InvalidArgument", "file_path is required")
	}
	fi, err := os.Stat(req.FilePath)
	if err != nil {
		return nil, fmt.Errorf("alipan: stat file failed: %w", err)
	}
	fileSize := fi.Size()
	name := req.Name
	if name == "" {
		name = filepath.Base(req.FilePath)
	}
	parentID := defaultStr(req.ParentFileID, "root")

	contentHash, preHash, err := computeSHA1Upper(req.FilePath)
	if err != nil {
		return nil, fmt.Errorf("alipan: compute sha1 failed: %w", err)
	}
	proofCode := ""
	if fileSize > 1024 {
		proofCode, err = computeProofCode(s.inv.AccessToken(), req.FilePath, fileSize)
		if err != nil {
			return nil, fmt.Errorf("alipan: compute proof_code failed: %w", err)
		}
	}

	createResp, err := s.createFileWithRapid(ctx, name, parentID, req.DriveID, req.CheckNameMode,
		fileSize, contentHash, preHash, proofCode)
	if err != nil {
		return nil, err
	}
	if createResp.RapidUpload || createResp.Exist {
		return s.Get(ctx, createResp.FileID, req.DriveID)
	}
	if err := s.uploadParts(ctx, req, createResp, fileSize); err != nil {
		return nil, err
	}
	return s.completeUpload(ctx, createResp.FileID, createResp.UploadID, req.DriveID, createResp.PartInfoList)
}

func (s *Service) createFileWithRapid(ctx context.Context, name, parentID, driveID string,
	mode types.CheckNameMode, fileSize int64, contentHash, preHash, proofCode string) (*createFileResp, error) {

	body := map[string]any{
		"name":              name,
		"type":              "file",
		"parent_file_id":    parentID,
		"drive_id":          driveID,
		"check_name_mode":   defaultStr(string(mode), "auto_rename"),
		"size":              fileSize,
		"content_hash_name": "sha1",
		"proof_version":     "v1",
	}
	if preHash != "" {
		body["pre_hash"] = preHash
	}
	csize := chunkSize(fileSize)
	partCount := int((fileSize + csize - 1) / csize)
	parts := make([]types.UploadPartInfo, partCount)
	for i := 0; i < partCount; i++ {
		parts[i] = types.UploadPartInfo{PartNumber: i + 1}
	}
	body["part_info_list"] = parts

	data, status, err := s.inv.Post(ctx, pathFileCreateWithFolders, body, nil, []int{201, 409})
	if err != nil {
		return nil, err
	}
	var resp createFileResp
	if status == 409 || (status == 201 && bytes.Contains(data, []byte(`"PreHashMatched"`))) {
		if err := json.Unmarshal(data, &resp); err == nil && resp.Code == "PreHashMatched" {
			body["content_hash"] = contentHash
			body["proof_code"] = proofCode
			delete(body, "pre_hash")
			data, status, err = s.inv.Post(ctx, pathFileCreateWithFolders, body, nil, []int{201})
			if err != nil {
				return nil, err
			}
		}
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("alipan: decode create response failed: %w", err)
	}
	return &resp, nil
}

func (s *Service) uploadParts(ctx context.Context, req *UploadRequest, createResp *createFileResp, fileSize int64) error {
	f, err := os.Open(req.FilePath)
	if err != nil {
		return err
	}
	defer f.Close()

	csize := chunkSize(fileSize)
	var sent int64
	if req.OnProgress != nil {
		req.OnProgress(0, fileSize)
	}
	for i, part := range createResp.PartInfoList {
		if part.UploadURL == "" {
			continue
		}
		partSize := csize
		remaining := fileSize - int64(i)*csize
		if remaining < partSize {
			partSize = remaining
		}
		buf := make([]byte, partSize)
		if _, err := io.ReadFull(f, buf); err != nil {
			return fmt.Errorf("alipan: read part %d failed: %w", part.PartNumber, err)
		}
		uploadURL := part.UploadURL
		if err := s.putPart(ctx, uploadURL, buf); err != nil {
			if is403(err) {
				newURL, rerr := s.renewUploadURL(ctx, createResp.DriveID, createResp.FileID, createResp.UploadID, part.PartNumber)
				if rerr != nil {
					return rerr
				}
				if err := s.putPart(ctx, newURL, buf); err != nil {
					return fmt.Errorf("alipan: upload part %d failed after renew: %w", part.PartNumber, err)
				}
			} else {
				return fmt.Errorf("alipan: upload part %d failed: %w", part.PartNumber, err)
			}
		}
		sent += int64(len(buf))
		if req.OnProgress != nil {
			req.OnProgress(sent, fileSize)
		}
	}
	return nil
}

func (s *Service) putPart(ctx context.Context, uploadURL string, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	setCommonHeaders(req)
	hc := &http.Client{Timeout: 10 * time.Minute}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return invoker.ParseAPIError(resp.StatusCode, body)
}

func (s *Service) renewUploadURL(ctx context.Context, driveID, fileID, uploadID string, partNumber int) (string, error) {
	body := map[string]any{
		"drive_id":  driveID,
		"file_id":   fileID,
		"upload_id": uploadID,
		"part_info_list": []types.UploadPartInfo{{PartNumber: partNumber}},
	}
	var resp struct {
		PartInfoList []types.UploadPartInfo `json:"part_info_list"`
	}
	if err := invoker.PostAndDecode(ctx, s.inv, pathFileGetUploadURL, body, &resp, []int{200}); err != nil {
		return "", err
	}
	if len(resp.PartInfoList) == 0 {
		return "", fmt.Errorf("alipan: renew upload url returned empty part_info_list")
	}
	return resp.PartInfoList[0].UploadURL, nil
}

func (s *Service) completeUpload(ctx context.Context, fileID, uploadID, driveID string, parts []types.UploadPartInfo) (*types.BaseFile, error) {
	body := map[string]any{
		"file_id":   fileID,
		"upload_id": uploadID,
		"drive_id":  driveID,
	}
	if parts != nil {
		body["part_info_list"] = parts
	}
	var f types.BaseFile
	if err := invoker.PostAndDecode(ctx, s.inv, pathFileComplete, body, &f, []int{200}); err != nil {
		return nil, err
	}
	return &f, nil
}

func is403(err error) bool {
	if e, ok := err.(*invoker.APIError); ok {
		return e.StatusCode == http.StatusForbidden
	}
	return false
}
