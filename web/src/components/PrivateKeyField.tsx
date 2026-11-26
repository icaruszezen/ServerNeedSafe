import React, { useRef, useState } from 'react';
import {
  Upload,
  FileKey2,
  X,
  Lock,
  AlertCircle,
  RefreshCw,
} from 'lucide-react';
import {
  formatKeyFileSize,
  KeyFileValidationError,
  readPrivateKeyFile,
  readPublicKeyFile,
  type ParsedPrivateKeyFile,
  type ParsedPublicKeyFile,
} from '../utils/sshKeyFile';

interface PrivateKeyFieldProps {
  idPrefix: string;
  textareaId?: string;
  label: React.ReactNode;
  labelHint?: React.ReactNode;
  value: string;
  onChange: (value: string) => void;
  uploadedFile: ParsedPrivateKeyFile | null;
  onFileLoaded: (parsed: ParsedPrivateKeyFile) => void;
  onClearFile: () => void;
  onPublicKeyFileLoaded?: (parsed: ParsedPublicKeyFile) => void;
  required?: boolean;
  placeholder?: string;
}

export const PrivateKeyField: React.FC<PrivateKeyFieldProps> = ({
  idPrefix,
  textareaId,
  label,
  labelHint,
  value,
  onChange,
  uploadedFile,
  onFileLoaded,
  onClearFile,
  onPublicKeyFileLoaded,
  required = false,
  placeholder = '-----BEGIN OPENSSH PRIVATE KEY----- ...',
}) => {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const dragDepthRef = useRef(0);
  const [dragging, setDragging] = useState(false);
  const [fileError, setFileError] = useState('');

  const processFiles = async (fileList: FileList | File[]) => {
    const files = Array.from(fileList);
    if (files.length === 0) return;
    setFileError('');

    let loadedPrivate: ParsedPrivateKeyFile | null = null;
    let loadedPublic: ParsedPublicKeyFile | null = null;
    let firstError = '';

    for (const file of files) {
      try {
        const parsedPriv = await readPrivateKeyFile(file);
        if (!loadedPrivate) {
          loadedPrivate = parsedPriv;
        }
      } catch (err) {
        if (
          err instanceof KeyFileValidationError &&
          err.code === 'IS_PUBLIC_KEY' &&
          onPublicKeyFileLoaded
        ) {
          try {
            const parsedPub = await readPublicKeyFile(file);
            if (!loadedPublic) {
              loadedPublic = parsedPub;
            }
            continue;
          } catch (pubErr: any) {
            if (!firstError) firstError = pubErr?.message || '读取公钥文件失败';
            continue;
          }
        }
        if (!firstError) {
          firstError = (err as Error)?.message || '读取密钥文件失败';
        }
      }
    }

    if (loadedPrivate) {
      onFileLoaded(loadedPrivate);
      if (loadedPublic && onPublicKeyFileLoaded) {
        onPublicKeyFileLoaded(loadedPublic);
      }
      setFileError('');
      return;
    }

    if (loadedPublic && onPublicKeyFileLoaded) {
      // User dropped/picked only a .pub file into the private key slot:
      // load it into the optional public key field AND remind them to also provide the private key.
      onPublicKeyFileLoaded(loadedPublic);
      setFileError(
        `已将公钥文件「${loadedPublic.fileName}」填入下方公钥栏，请再上传对应的 SSH 私钥文件（如 id_ed25519、.pem）`
      );
      return;
    }

    setFileError(firstError || '未能识别有效的 SSH 私钥文件');
  };

  const handleInputChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      await processFiles(files);
    }
    // Reset input value so re-selecting the same file always triggers onChange.
    e.target.value = '';
  };

  const handleDragEnter = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragDepthRef.current += 1;
    setDragging(true);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragDepthRef.current = Math.max(0, dragDepthRef.current - 1);
    if (dragDepthRef.current === 0) {
      setDragging(false);
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragDepthRef.current = 0;
    setDragging(false);
    if (e.dataTransfer?.files && e.dataTransfer.files.length > 0) {
      await processFiles(e.dataTransfer.files);
    }
  };

  const triggerPicker = () => {
    setFileError('');
    fileInputRef.current?.click();
  };

  const formatSummary = uploadedFile
    ? uploadedFile.keyTypeHint
      ? `${uploadedFile.formatLabel} · ${uploadedFile.keyTypeHint}`
      : uploadedFile.formatLabel
    : '';

  return (
    <div className="field">
      <label className="field-label" htmlFor={textareaId || `${idPrefix}-textarea`}>
        <span>{label}</span>
        {labelHint && <span className="field-hint">{labelHint}</span>}
      </label>

      <input
        ref={fileInputRef}
        id={`${idPrefix}-file-input`}
        type="file"
        multiple={Boolean(onPublicKeyFileLoaded)}
        style={{ display: 'none' }}
        onChange={(e) => void handleInputChange(e)}
      />

      <div
        id={`${idPrefix}-upload-zone`}
        className={`key-upload-zone ${uploadedFile ? 'loaded' : ''} ${dragging ? 'dragging' : ''}`}
        role={uploadedFile ? undefined : 'button'}
        tabIndex={uploadedFile ? undefined : 0}
        aria-label={uploadedFile ? undefined : '上传或拖拽 SSH 私钥文件'}
        onClick={() => {
          if (!uploadedFile) triggerPicker();
        }}
        onKeyDown={(e) => {
          if (!uploadedFile && (e.key === 'Enter' || e.key === ' ')) {
            e.preventDefault();
            triggerPicker();
          }
        }}
        onDragEnter={handleDragEnter}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={(e) => void handleDrop(e)}
      >
        {uploadedFile && !dragging ? (
          <>
            <div className="key-upload-icon loaded">
              <FileKey2 size={16} />
            </div>
            <div className="key-upload-info">
              <div className="key-upload-title-row">
                <span className="key-upload-filename mono" title={uploadedFile.fileName}>
                  {uploadedFile.fileName}
                </span>
                <span className="key-upload-size mono">
                  {formatKeyFileSize(uploadedFile.fileSize)}
                </span>
              </div>
              <div className="key-upload-badges">
                <span className="tag-chip teal">{formatSummary}</span>
                {uploadedFile.encrypted && (
                  <span className="tag-chip amber">
                    <Lock size={10.5} /> 受口令保护 · 请填写下方口令
                  </span>
                )}
              </div>
            </div>
            <div className="key-upload-actions">
              <button
                type="button"
                id={`${idPrefix}-replace-file-btn`}
                className="btn btn-sm"
                onClick={(e) => {
                  e.stopPropagation();
                  triggerPicker();
                }}
              >
                <RefreshCw size={12.5} /> 更换文件
              </button>
              <button
                type="button"
                id={`${idPrefix}-clear-file-btn`}
                className="btn btn-ghost btn-sm btn-icon"
                title="清除已上传文件"
                onClick={(e) => {
                  e.stopPropagation();
                  setFileError('');
                  onClearFile();
                }}
              >
                <X size={14} />
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="key-upload-icon">
              <Upload size={16} />
            </div>
            <div className="key-upload-info">
              <div className="key-upload-prompt">
                {dragging
                  ? uploadedFile
                    ? '松开鼠标替换当前密钥文件'
                    : '松开鼠标立即读取密钥文件'
                  : '点击选择或拖拽 SSH 私钥文件至此上传'}
              </div>
              <div className="key-upload-sub">
                {onPublicKeyFileLoaded
                  ? '支持 id_ed25519、id_rsa、.pem、.key（可同时拖入 .pub，≤\u00A0256\u00A0KB）'
                  : '支持 id_ed25519、id_rsa、.pem、.key 等 OpenSSH / PEM 格式（≤\u00A0256\u00A0KB）'}
              </div>
            </div>
            <div className="key-upload-actions">
              <button
                type="button"
                id={`${idPrefix}-choose-file-btn`}
                className="btn btn-sm"
                onClick={(e) => {
                  e.stopPropagation();
                  triggerPicker();
                }}
              >
                <Upload size={12.5} /> 选择文件
              </button>
            </div>
          </>
        )}
      </div>

      {fileError && (
        <div className="key-upload-error" role="alert">
          <AlertCircle size={13.5} style={{ flexShrink: 0, marginTop: 1 }} />
          <span>{fileError}</span>
        </div>
      )}

      <div className="key-textarea-caption">
        <span>{uploadedFile ? '已从本地文件载入私钥内容（可核对或编辑）' : '或直接粘贴私钥 PEM 内容'}</span>
      </div>

      <textarea
        id={textareaId || `${idPrefix}-textarea`}
        className="textarea mono code-textarea"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        required={required}
      />
    </div>
  );
};
