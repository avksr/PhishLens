// ────────────────────────────────────────────────────────────
//  PhishLens  ·  UploadDropzone Component
//  Drag-and-drop file upload with strict frontend validation:
//  - Allowed types: JPG, PNG, PDF
//  - Max file size: 5MB
//  - Clear error messages for validation failures
// ────────────────────────────────────────────────────────────

import { useState, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

// ── Constants ────────────────────────────────────────────────

const ALLOWED_TYPES: Record<string, string> = {
  'image/jpeg': 'JPG',
  'image/png': 'PNG',
  'application/pdf': 'PDF',
};

const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.pdf'];
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

// ── Helpers ──────────────────────────────────────────────────

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function getFileIcon(type: string): string {
  if (type === 'image/jpeg' || type === 'image/png') return '🖼️';
  if (type === 'application/pdf') return '📄';
  return '📎';
}

// ── Validation ──────────────────────────────────────────────

interface ValidationResult {
  valid: boolean;
  error?: string;
}

function validateFile(file: File): ValidationResult {
  // Check file type
  if (!ALLOWED_TYPES[file.type]) {
    const ext = file.name.split('.').pop()?.toLowerCase();
    if (!ext || !ALLOWED_EXTENSIONS.includes(`.${ext}`)) {
      return {
        valid: false,
        error: `Unsupported file type "${file.name.split('.').pop()?.toUpperCase() ?? 'UNKNOWN'}". Only JPG, PNG, and PDF files are allowed.`,
      };
    }
  }

  // Check file size
  if (file.size > MAX_FILE_SIZE) {
    return {
      valid: false,
      error: `File too large (${formatFileSize(file.size)}). Maximum allowed size is 5MB.`,
    };
  }

  // Check for empty files
  if (file.size === 0) {
    return {
      valid: false,
      error: 'File is empty. Please select a valid file.',
    };
  }

  return { valid: true };
}

// ── Component Props ──────────────────────────────────────────

interface UploadDropzoneProps {
  /** Called when a valid file is accepted */
  onFileAccepted?: (file: File) => void;
  /** Disable the dropzone */
  disabled?: boolean;
}

// ── Component ────────────────────────────────────────────────

export function UploadDropzone({ onFileAccepted, disabled = false }: UploadDropzoneProps) {
  const [isDragOver, setIsDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [acceptedFile, setAcceptedFile] = useState<File | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const processFile = useCallback(
    (file: File) => {
      setError(null);
      setAcceptedFile(null);

      const result = validateFile(file);
      if (!result.valid) {
        setError(result.error!);
        return;
      }

      setAcceptedFile(file);
      onFileAccepted?.(file);
    },
    [onFileAccepted]
  );

  // ── Drag Handlers ──────────────────────────────────────────

  const handleDragOver = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      if (!disabled) setIsDragOver(true);
    },
    [disabled]
  );

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragOver(false);

      if (disabled) return;

      const files = e.dataTransfer.files;
      if (files.length === 0) return;
      if (files.length > 1) {
        setError('Only one file can be uploaded at a time.');
        return;
      }
      processFile(files[0]);
    },
    [disabled, processFile]
  );

  // ── Click-to-browse Handler ────────────────────────────────

  const handleInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const files = e.target.files;
      if (!files || files.length === 0) return;
      processFile(files[0]);
      // Reset input so re-selecting the same file triggers onChange
      e.target.value = '';
    },
    [processFile]
  );

  const handleClearFile = useCallback(() => {
    setAcceptedFile(null);
    setError(null);
  }, []);

  // ── Render ────────────────────────────────────────────────

  return (
    <div className="w-full">
      {/* ── Dropzone Area ── */}
      <div
        role="button"
        tabIndex={disabled ? -1 : 0}
        aria-label="Upload file dropzone — drag and drop or click to browse"
        aria-disabled={disabled}
        onClick={() => !disabled && inputRef.current?.click()}
        onKeyDown={(e) => {
          if ((e.key === 'Enter' || e.key === ' ') && !disabled) {
            e.preventDefault();
            inputRef.current?.click();
          }
        }}
        onDragOver={handleDragOver}
        onDragEnter={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`
          relative flex flex-col items-center justify-center gap-3
          w-full min-h-[140px] p-6
          rounded-xl border-2 border-dashed
          transition-all duration-300 cursor-pointer
          ${disabled
            ? 'border-zinc-800 bg-zinc-950/50 opacity-50 cursor-not-allowed'
            : isDragOver
              ? 'border-cyan-400 bg-cyan-500/[0.06] shadow-[0_0_24px_rgba(0,240,255,0.12)] scale-[1.01]'
              : error
                ? 'border-rose-500/40 bg-rose-500/[0.03] hover:border-rose-500/50'
                : acceptedFile
                  ? 'border-emerald-500/30 bg-emerald-500/[0.03] hover:border-emerald-500/40'
                  : 'border-white/[0.1] bg-white/[0.01] hover:border-cyan-500/30 hover:bg-cyan-500/[0.02]'
          }
        `}
      >
        {/* Hidden file input */}
        <input
          ref={inputRef}
          type="file"
          accept=".jpg,.jpeg,.png,.pdf"
          onChange={handleInputChange}
          disabled={disabled}
          className="sr-only"
          aria-hidden="true"
        />

        {/* Drop zone content */}
        <AnimatePresence mode="wait">
          {isDragOver ? (
            <motion.div
              key="drag-over"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="flex flex-col items-center gap-2"
            >
              <div className="size-12 rounded-xl bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-xl animate-pulse">
                📥
              </div>
              <p className="text-sm font-semibold text-cyan-400 font-sans m-0">
                Drop file here
              </p>
            </motion.div>
          ) : acceptedFile ? (
            <motion.div
              key="accepted"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              className="flex items-center gap-3 w-full"
            >
              <div className="size-11 rounded-xl bg-emerald-500/10 border border-emerald-500/25 flex items-center justify-center text-lg shrink-0">
                {getFileIcon(acceptedFile.type)}
              </div>
              <div className="flex-1 min-w-0">
                <p className="m-0 text-sm font-semibold text-zinc-100 font-sans truncate">
                  {acceptedFile.name}
                </p>
                <p className="m-0 text-[11px] text-zinc-500 font-mono">
                  {formatFileSize(acceptedFile.size)} · {ALLOWED_TYPES[acceptedFile.type] ?? acceptedFile.name.split('.').pop()?.toUpperCase()}
                </p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/30">
                  ✓ Valid
                </span>
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    handleClearFile();
                  }}
                  className="size-7 rounded-lg flex items-center justify-center text-zinc-500 hover:text-zinc-300 hover:bg-white/[0.05] transition-colors cursor-pointer"
                  aria-label="Remove file"
                >
                  ✕
                </button>
              </div>
            </motion.div>
          ) : (
            <motion.div
              key="empty"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="flex flex-col items-center gap-2.5"
            >
              <div className="size-12 rounded-xl bg-white/[0.03] border border-white/[0.08] flex items-center justify-center text-xl">
                📂
              </div>
              <div className="text-center">
                <p className="m-0 text-sm font-semibold text-zinc-300 font-sans">
                  Drop evidence file or{' '}
                  <span className="text-cyan-400 underline underline-offset-2 decoration-cyan-400/30">
                    browse
                  </span>
                </p>
                <p className="m-0 mt-1 text-[11px] text-zinc-600 font-mono">
                  JPG, PNG, PDF · Max 5MB
                </p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* ── Error Message ── */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -4, height: 0 }}
            animate={{ opacity: 1, y: 0, height: 'auto' }}
            exit={{ opacity: 0, y: -4, height: 0 }}
            transition={{ duration: 0.2 }}
            role="alert"
            className="mt-2.5 flex items-start gap-2 px-3.5 py-2.5 rounded-xl bg-rose-500/8 border border-rose-500/25"
          >
            <span aria-hidden className="text-rose-400 text-sm shrink-0 mt-0.5">⚠</span>
            <div className="flex-1 min-w-0">
              <p className="m-0 text-xs font-semibold text-rose-400 font-sans">
                Validation Failed
              </p>
              <p className="m-0 mt-0.5 text-[11px] text-rose-300/80 font-sans leading-relaxed">
                {error}
              </p>
            </div>
            <button
              type="button"
              onClick={() => setError(null)}
              className="text-rose-500/60 hover:text-rose-400 text-xs transition-colors cursor-pointer shrink-0"
              aria-label="Dismiss error"
            >
              ✕
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default UploadDropzone;
