'use client';

import React from 'react';
import styles from './FileList.module.css';

interface FileListProps {
    files: File[];
    onReorder: (newFiles: File[]) => void;
    onRemove: (index: number) => void;
    results?: any;
    onDownload?: (base64: string, filename: string) => void;
}

export default function FileList({ files, onReorder, onRemove, results, onDownload }: FileListProps) {
    const [draggedIndex, setDraggedIndex] = React.useState<number | null>(null);
    const [dragOverIndex, setDragOverIndex] = React.useState<number | null>(null);

    const handleDragStart = (e: React.DragEvent<HTMLLIElement>, index: number) => {
        setDraggedIndex(index);
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/html', index.toString());

        // Add ghost image styling
        if (e.currentTarget) {
            e.currentTarget.style.opacity = '0.5';
        }
    };

    const handleDragEnd = (e: React.DragEvent<HTMLLIElement>) => {
        setDraggedIndex(null);
        setDragOverIndex(null);

        // Reset opacity
        if (e.currentTarget) {
            e.currentTarget.style.opacity = '1';
        }
    };

    const handleDragOver = (e: React.DragEvent<HTMLLIElement>) => {
        e.preventDefault(); // Necessary to allow drop
        e.dataTransfer.dropEffect = 'move';
    };

    const handleDragEnter = (e: React.DragEvent<HTMLLIElement>, index: number) => {
        e.preventDefault();
        if (draggedIndex !== null && draggedIndex !== index) {
            setDragOverIndex(index);
        }
    };

    const handleDragLeave = (e: React.DragEvent<HTMLLIElement>) => {
        // Only clear if leaving the list entirely
        const rect = e.currentTarget.getBoundingClientRect();
        const x = e.clientX;
        const y = e.clientY;

        if (x < rect.left || x >= rect.right || y < rect.top || y >= rect.bottom) {
            setDragOverIndex(null);
        }
    };

    const handleDrop = (e: React.DragEvent<HTMLLIElement>, dropIndex: number) => {
        e.preventDefault();
        e.stopPropagation();

        if (draggedIndex === null || draggedIndex === dropIndex) {
            setDragOverIndex(null);
            return;
        }

        // Reorder the files array
        const newFiles = [...files];
        const [draggedFile] = newFiles.splice(draggedIndex, 1);
        newFiles.splice(dropIndex, 0, draggedFile);

        onReorder(newFiles);
        setDraggedIndex(null);
        setDragOverIndex(null);
    };

    const formatFileSize = (bytes: number): string => {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
    };

    return (
        <div className={styles.fileListContainer}>
            <div className={styles.fileListHeader}>
                <h3>{files.length} file{files.length !== 1 ? 's' : ''} selected</h3>
                <p className={styles.hint}>Drag to reorder</p>
            </div>

            <ul className={styles.fileList}>
                {files.map((file, index) => (
                    <li
                        key={`${file.name}-${index}`}
                        draggable
                        onDragStart={(e) => handleDragStart(e, index)}
                        onDragEnd={handleDragEnd}
                        onDragOver={handleDragOver}
                        onDragEnter={(e) => handleDragEnter(e, index)}
                        onDragLeave={handleDragLeave}
                        onDrop={(e) => handleDrop(e, index)}
                        className={`${styles.fileItem} ${draggedIndex === index ? styles.dragging : ''
                            } ${dragOverIndex === index ? styles.dragOver : ''}`}
                    >
                        <div className={styles.dragHandle}>
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
                                <path d="M8 6h8M8 12h8M8 18h8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                            </svg>
                        </div>

                        <div className={styles.fileNumber}>
                            {index + 1}
                        </div>

                        <div className={styles.fileInfo}>
                            <div className={styles.fileName}>{file.name}</div>
                            <div className={styles.fileSize}>{formatFileSize(file.size)}</div>
                        </div>

                        {results && results.files && results.files[index] && files.length > 1 ? (
                            <button
                                type="button"
                                className={styles.downloadButton}
                                onClick={(e) => {
                                    e.stopPropagation();
                                    const fileData = results.files[index];
                                    if (fileData && fileData.redactedBase64 && onDownload) {
                                        const base64 = fileData.redactedBase64;
                                        const filename = fileData.filename || files[index].name;
                                        onDownload(base64, `redacted-${filename}`);
                                    }
                                }}
                                title="Download redacted"
                            >
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
                                    <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4m4-5l5 5m0 0l5-5m-5 5V3" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                                </svg>
                                Download
                            </button>
                        ) : results && results.files && results.files[index] && files.length === 1 ? (
                            null
                        ) : (
                            <button
                                type="button"
                                className={styles.removeButton}
                                onClick={(e) => {
                                    e.stopPropagation();
                                    onRemove(index);
                                }}
                                title="Remove file"
                            >
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
                                    <path d="M18 6L6 18M6 6l12 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                                </svg>
                            </button>
                        )
                        }</li>
                ))}
            </ul>
        </div>
    );
}
