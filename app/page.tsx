'use client';

import { useState, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { createClient } from '@/lib/supabase/client';
import FileList from './components/FileList';
import styles from './page.module.css';

// Helper to download a base64‑encoded PDF
function downloadBase64(base64: string, filename: string) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  const blob = new Blob([bytes], { type: 'application/pdf' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function Home() {
  const [files, setFiles] = useState<File[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  // Removed redactedPdfUrl state – we now use base64 data from the API response.
  const [dragOver, setDragOver] = useState(false);
  const [piiCount, setPiiCount] = useState<number>(0);
  const [results, setResults] = useState<any>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const router = useRouter();
  const supabase = createClient();

  const handleLogout = async () => {
    await supabase.auth.signOut();
    router.push('/login');
    router.refresh();
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFiles = Array.from(e.target.files || []);
    if (selectedFiles.length === 0) return;
    const validFiles = selectedFiles.filter(f => f.type === "application/pdf");
    if (validFiles.length !== selectedFiles.length) {
      setError("Only PDF files are allowed.");
      return;
    }

    // Allow 1–10 files
    if (files.length + validFiles.length > 10) {
      setError("You can upload a maximum of 10 PDF files.");
      return;
    }

    // Success
    setFiles(prevFiles => [...prevFiles, ...validFiles]);
    setError(null);
    setSuccess(false);
    setPiiCount(0);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);

    const droppedFiles = Array.from(e.dataTransfer.files || []);
    const validFiles = droppedFiles.filter(f => f.type === "application/pdf");

    if (validFiles.length !== droppedFiles.length) {
      setError("Only PDF files are allowed.");
      return;
    }

    // Allow 1–10 files
    if (files.length + validFiles.length > 10) {
      setError("You can upload a maximum of 10 PDF files.");
      return;
    }

    setFiles(prevFiles => [...prevFiles, ...validFiles]);
    setError(null);
    setSuccess(false);
    setPiiCount(0);
  };

  const handleUpload = async () => {
    if (files.length === 0) {
      setError('Please select at least one PDF file.');
      return;
    }

    setLoading(true);
    setError(null);
    setSuccess(false);

    try {
      const formData = new FormData();
      files.forEach((f) => {
        formData.append('files[]', f);
      });

      const response = await fetch('/api/redact-pdf', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to redact PDF');
      }

      // Parse JSON response containing per‑file data and combined base64
      const json = await response.json();
      setResults(json);

      // Update PII count if header is present (fallback to json.totalEntities)
      const piiCountHeader = response.headers.get('X-PII-Entities-Found');
      if (piiCountHeader) {
        setPiiCount(parseInt(piiCountHeader, 10));
      } else if (json.totalEntities !== undefined) {
        setPiiCount(json.totalEntities);
      }

      setSuccess(true);
    } catch (err: any) {
      setError(err.message || 'An error occurred while processing the PDF');
    } finally {
      setLoading(false);
    }
  };

  // Download the combined redacted PDF (base64) from the API response
  const handleDownload = () => {
    if (results?.combinedBase64) {
      downloadBase64(results.combinedBase64, 'merged-redacted.pdf');
    }
  };

  const handleReset = () => {
    setFiles([]);
    setError(null);
    setSuccess(false);
    setResults(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleReorder = (newFiles: File[]) => {
    setFiles(newFiles);
  };

  const handleRemoveFile = (index: number) => {
    setFiles(files.filter((_, i) => i !== index));
  };

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div className={styles.headerTop}>
          <div className={styles.iconWrapper}>
            <img src="/dga-logo.svg" alt="DGA Logo" width="48" height="48" />
          </div>
          <button onClick={handleLogout} className={styles.logoutButton} title="Logout">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
            </svg>
          </button>
        </div>
        <h1 className={styles.title}>
          <span className="text-gradient">DGA Document AI Agent</span>
        </h1>
        <p className={styles.subtitle}>
          Automatically detect and redact sensitive information from your documents using Gosign AI Infrastructure
        </p>
      </div>

      <div className={`${styles.card} glass-card fade-in`}>
        <div
          className={`upload-zone ${dragOver ? 'drag-over' : ''}`}
          onDragOver={success ? undefined : handleDragOver}
          onDragLeave={success ? undefined : handleDragLeave}
          onDrop={success ? undefined : handleDrop}
          onClick={success ? undefined : () => fileInputRef.current?.click()}
          style={success ? { cursor: 'default' } : {}}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept="application/pdf"
            multiple
            onChange={handleFileChange}
            style={{ display: 'none' }}
            disabled={success}
          />

          {success ? (
            <>
              <div className={styles.uploadIcon}>
                <svg width="80" height="80" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <circle cx="12" cy="12" r="10" stroke="hsl(142, 76%, 56%)" strokeWidth="2" />
                  <path className="checkmark" d="M8 12l3 3l5-5" stroke="hsl(142, 76%, 56%)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </div>
              <h3 className={styles.uploadTitle}>Redaction Complete!</h3>
              <p className={styles.uploadText}>
                {piiCount > 0
                  ? `Successfully detected and redacted ${piiCount} ${piiCount === 1 ? 'entity' : 'entities'}`
                  : 'Your PDFs have been successfully processed'}
              </p>
              <p className={styles.uploadHint}>
                Download individual files below or click "Download All (Merged)"
              </p>
            </>
          ) : (
            <>
              <div className={styles.uploadIcon}>
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M7 18a4.6 4.4 0 0 1 0 -9a5 4.5 0 0 1 11 2h1a3.5 3.5 0 0 1 0 7h-1" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  <path d="M9 15l3-3l3 3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  <path d="M12 12v9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </div>

              {files.length > 0 ? (
                <>
                  <h3 className={styles.uploadTitle}>Drop your PDFs here</h3>
                  <p className={styles.uploadText}>or click to add more files</p>
                </>
              ) : (
                <>
                  <h3 className={styles.uploadTitle}>Drop your PDFs here</h3>
                  <p className={styles.uploadText}>or click to browse</p>
                </>
              )}
              <p className={styles.uploadHint}>
                Supports PDF files up to 50MB
              </p>
            </>
          )}
        </div>

        {files.length > 0 && (
          <FileList
            files={files}
            onReorder={handleReorder}
            onRemove={handleRemoveFile}
            results={results}
            onDownload={downloadBase64}
          />
        )}

        {success && piiCount > 0 && (
          <div className={styles.successText} style={{ marginTop: '1rem', textAlign: 'center' }}>
            Successfully detected and redacted {piiCount} {piiCount === 1 ? 'entity' : 'entities'} using Gosign AI.
          </div>
        )}

        {error && (
          <div className={styles.error}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2" />
              <path d="M12 8v4m0 4h.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
            </svg>
            {error}
          </div>
        )}

        <div className={styles.actions}>
          {!success && (
            <button
              className="btn btn-primary"
              onClick={handleUpload}
              disabled={files.length === 0 || loading}
            >
              {loading ? (
                <>
                  <div className="spinner" style={{ width: '20px', height: '20px', borderWidth: '2px' }}></div>
                  Processing...
                </>
              ) : (
                <>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M5 13l4 4L19 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                  Redact & Combine Documents
                </>
              )}
            </button>
          )}

          {success && results?.combinedBase64 && (
            <button className="btn btn-primary" onClick={handleDownload}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4m4-5l5 5m0 0l5-5m-5 5V3" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              {files.length > 1 ? 'Download All (Merged)' : 'Download'}
            </button>
          )}

          {files.length > 0 && !loading && (
            <button className="btn btn-secondary" onClick={handleReset}>
              {success ? 'Process Another File' : 'Clear'}
            </button>
          )}
        </div>
      </div>

      <div className={styles.features}>
        <div className={styles.feature}>
          <div className={styles.featureIcon}>🔒</div>
          <h3>Secure Processing</h3>
          <p>Your documents are processed securely using Gosign AI Infrastructure</p>
        </div>
        <div className={styles.feature}>
          <div className={styles.featureIcon}>⚡</div>
          <h3>Fast & Accurate</h3>
          <p>Advanced Gosign AI detects with high precision</p>
        </div>
        <div className={styles.feature}>
          <div className={styles.featureIcon}>🎯</div>
          <h3>Comprehensive</h3>
          <p>Detects names, emails, addresses, phone numbers & more</p>
        </div>
      </div>
    </div>
  );
}
