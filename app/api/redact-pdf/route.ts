import { NextRequest, NextResponse } from 'next/server';
import axios from 'axios';
import { PDFDocument, rgb, degrees } from 'pdf-lib';

// Custom type for uploaded file with buffer
interface UploadedFile {
    filepath: string;
    originalFilename: string | null;
    mimetype: string | null;
    size: number;
    buffer: Buffer;
}

// Azure PII Entity interface
interface PIIEntity {
    text: string;
    category: string;
    offset: number;
    length: number;
    confidenceScore: number;
}

// Azure Document Intelligence Interfaces
interface DocIntelWord {
    content: string;
    polygon: number[]; // [x1, y1, x2, y2, x3, y3, x4, y4]
    span: {
        offset: number;
        length: number;
    };
    confidence: number;
}

interface DocIntelPage {
    pageNumber: number;
    angle: number;
    width: number;
    height: number;
    unit: 'pixel' | 'inch';
    words: DocIntelWord[];
}

interface DocIntelResponse {
    status: string;
    analyzeResult: {
        content: string;
        pages: DocIntelPage[];
    };
}

// Azure API Response interface (PII)
interface AzurePIIResponse {
    kind: string;
    results: {
        documents: Array<{
            id: string;
            entities: PIIEntity[];
            redactedText: string;
        }>;
        errors: any[];
        modelVersion: string;
    };
}

// Redaction coordinate for PyMuPDF
interface RedactionCoordinate {
    pageIndex: number;
    x: number;
    y: number;
    width: number;
    height: number;
    text?: string;
    category?: string;
}

// Helper function to parse form data for multiple files
async function parseForm(req: NextRequest): Promise<{ fields: any; files: UploadedFile[] }> {
    const formData = await req.formData();
    const filesArray = formData.getAll('files[]') as File[];

    if (!filesArray || filesArray.length === 0) {
        throw new Error('No files uploaded');
    }

    // Convert all Files to UploadedFile objects with Buffers
    const uploadedFiles: UploadedFile[] = [];

    for (const file of filesArray) {
        const bytes = await file.arrayBuffer();
        const buffer = Buffer.from(bytes);

        uploadedFiles.push({
            filepath: '',
            originalFilename: file.name,
            mimetype: file.type,
            size: file.size,
            buffer: buffer,
        });
    }

    return {
        fields: {},
        files: uploadedFiles,
    };
}

// Extract text using Azure Document Intelligence (OCR)
async function extractTextWithAzureDocIntel(
    pdfBuffer: Buffer,
    endpoint: string,
    apiKey: string
): Promise<DocIntelResponse['analyzeResult']> {
    // API Version 2023-07-31 (General Availability)
    const cleanEndpoint = endpoint.trim().replace(/\/$/, '');
    // Try the /formrecognizer path which is compatible with more resources
    const url = `${cleanEndpoint}/formrecognizer/documentModels/prebuilt-read:analyze?api-version=2023-07-31`;

    console.log('Calling Azure Document Intelligence:', url);

    try {
        const response = await axios.post(url, pdfBuffer, {
            headers: {
                'Ocp-Apim-Subscription-Key': apiKey,
                'Content-Type': 'application/pdf',
            }
        });

        // Note: The API might return 202 Accepted for large files and require polling.
        // However, for smaller files, it might return 200 OK directly or we might need to handle the Operation-Location header.
        // Let's check if it's async.

        if (response.status === 202) {
            const operationLocation = response.headers['operation-location'];
            if (!operationLocation) {
                throw new Error('Azure accepted the request but returned no Operation-Location header.');
            }

            console.log('Waiting for Azure Document Intelligence analysis...');

            // Poll for results
            let status = 'running';
            let resultResponse;

            while (status === 'running' || status === 'notStarted') {
                await new Promise(resolve => setTimeout(resolve, 1000)); // Wait 1 second
                resultResponse = await axios.get(operationLocation, {
                    headers: { 'Ocp-Apim-Subscription-Key': apiKey }
                });
                status = resultResponse.data.status;
                console.log('Analysis status:', status);

                if (status === 'failed') {
                    throw new Error('Azure Document Intelligence analysis failed.');
                }
            }

            return resultResponse?.data.analyzeResult;
        }

        // If it returns 200 OK directly (unlikely for this API, but possible for some versions)
        return response.data.analyzeResult;

    } catch (error: any) {
        console.error('Azure Document Intelligence Error:', error.response?.data || error.message);
        throw new Error(`OCR failed: ${error.response?.data?.error?.message || error.message}`);
    }
}

// Detect language automatically
async function detectLanguage(text: string, endpoint: string, apiKey: string): Promise<string> {
    const cleanEndpoint = endpoint.trim().replace(/\/$/, '');
    const url = `${cleanEndpoint}/language/:analyze-text?api-version=2023-04-01`;

    const requestBody = {
        kind: 'LanguageDetection',
        parameters: {},
        analysisInput: {
            documents: [
                {
                    id: '1',
                    text: text.substring(0, 1000) // Use first 1000 chars for detection
                }
            ]
        }
    };

    try {
        const response = await axios.post(url, requestBody, {
            headers: {
                'Ocp-Apim-Subscription-Key': apiKey,
                'Content-Type': 'application/json'
            }
        });

        const detectedLang = response.data.results?.documents?.[0]?.detectedLanguage?.iso6391Name;
        console.log('Detected language:', detectedLang || 'en');
        return detectedLang || 'en';
    } catch (error) {
        console.error('Language detection failed, defaulting to English');
        return 'en';
    }
}

// Call Azure PII Detection API with chunking support
async function detectPII(text: string, endpoint: string, apiKey: string, language: string = 'en'): Promise<PIIEntity[]> {
    const cleanEndpoint = endpoint.trim().replace(/\/$/, '');
    const url = `${cleanEndpoint}/language/:analyze-text?api-version=2023-04-01`;

    console.log('Calling Azure PII Detection API:', url);
    console.log('Using language:', language);
    console.log('Text sample (first 500 chars):', text.substring(0, 500));

    // Azure PII API limit is 5,120 characters
    const CHUNK_SIZE = 5000;
    const allEntities: PIIEntity[] = [];

    const piiCategories = [
        // Personal Information
        'Person', 'PersonType', 'Email', 'PhoneNumber', 'Address',
        // Dates
        // 'DateTime', 'Age',
        // Financial
        'CreditCardNumber', 'EUDebitCardNumber', 'InternationalBankingAccountNumber',
        'SWIFTCode', 'ABARoutingNumber', 'USBankAccountNumber',
        // Government IDs - US
        'USSocialSecurityNumber', 'USDriversLicenseNumber', 'USPassportNumber',
        // Government IDs - EU
        'EUDriversLicenseNumber', 'EUPassportNumber', 'EUNationalIdentificationNumber',
        'EUTaxIdentificationNumber', 'EUGPSCoordinates',
        // Government IDs - Other Countries
        'AUDriversLicenseNumber', 'AUMedicalAccountNumber', 'AUPassportNumber', 'AUTaxFileNumber',
        'CADriversLicenseNumber', 'CAHealthServiceNumber', 'CAPassportNumber', 'CASocialInsuranceNumber',
        'CHSocialSecurityNumber',
        'CNResidentIdentityCardNumber',
        'INPermanentAccountNumber', 'INUniqueIdentificationNumber',
        'JPDriversLicenseNumber', 'JPPassportNumber', 'JPResidentRegistrationNumber', 'JPSocialInsuranceNumber',
        'NZDriversLicenseNumber', 'NZSocialWelfareNumber',
        'UKDriversLicenseNumber', 'UKNationalHealthNumber', 'UKNationalInsuranceNumber', 'UKPassportNumber',
        // Country-specific IDs
        'ATIdentityCard', 'ATTaxIdentificationNumber', 'ATValueAddedTaxNumber',
        'BEDriversLicenseNumber', 'BENationalNumber', 'BEValueAddedTaxNumber',
        'BRCPFNumber', 'BRLegalEntityNumber', 'BRNationalIDRG',
        'BGUniformCivilNumber',
        'HRIdentityCardNumber', 'HRNationalIDNumber', 'HRPersonalIdentificationNumber',
        'CYIdentityCard', 'CYTaxIdentificationNumber',
        'CZPersonalIdentityNumber',
        'DKPersonalIdentificationNumber',
        'EEPersonalIdentificationCode',
        'FIEuropeanHealthNumber', 'FINationalID', 'FIPassportNumber',
        'FRDriversLicenseNumber', 'FRHealthInsuranceNumber', 'FRNationalID', 'FRPassportNumber', 'FRSocialSecurityNumber', 'FRTaxIdentificationNumber', 'FRValueAddedTaxNumber',
        'DEDriversLicenseNumber', 'DEPassportNumber', 'DEIdentityCardNumber', 'DETaxIdentificationNumber', 'DEValueAddedTaxNumber',
        'GRNationalIDCard', 'GRTaxIdentificationNumber',
        'HKIdentityCardNumber',
        'HUPersonalIdentificationNumber', 'HUTaxIdentificationNumber', 'HUValueAddedTaxNumber',
        'IEPersonalPublicServiceNumber',
        'ILBankAccountNumber', 'ILNationalID',
        'ITDriversLicenseNumber', 'ITFiscalCode',
        'LVPersonalCode',
        'LTPersonalCode',
        'LUNationalIdentificationNumberNatural', 'LUNationalIdentificationNumberNonNatural',
        'MTIdentityCardNumber', 'MTTaxIDNumber',
        'NLCitizensServiceNumber', 'NLTaxIdentificationNumber', 'NLValueAddedTaxNumber',
        'NOIdentityNumber',
        'PHUnifiedMultiPurposeIDNumber',
        'PLIdentityCard', 'PLNationalID', 'PLPassportNumber', 'PLTaxIdentificationNumber', 'PLREGONNumber',
        'PTCitizenCardNumber', 'PTTaxIdentificationNumber',
        'ROPersonalNumericalCode',
        'RUPassportNumberDomestic', 'RUPassportNumberInternational',
        'SANationalID',
        'SGNationalRegistrationIdentityCardNumber',
        'SKPersonalNumber',
        'SITaxIdentificationNumber', 'SIUniqueMasterCitizenNumber',
        'ZAIdentificationNumber',
        'KRResidentRegistrationNumber',
        'ESDriversLicenseNumber', 'ESSocialSecurityNumber', 'ESTaxIdentificationNumber',
        'SEDriversLicenseNumber', 'SENationalID', 'SEPassportNumber', 'SETaxIdentificationNumber',
        'CHTaxIdentificationNumber',
        'TRNationalIdentificationNumber',
        'UAPassportNumberDomestic', 'UAPassportNumberInternational',
        // Organizations and URLs
        'Organization', 'URL', 'IPAddress'
    ];

    // If text is small enough, process in one request
    if (text.length <= CHUNK_SIZE) {
        const requestBody = {
            kind: 'PiiEntityRecognition',
            parameters: {
                modelVersion: 'latest',
                domain: 'none',
                piiCategories: piiCategories
            },
            analysisInput: {
                documents: [
                    {
                        id: '1',
                        language: language,
                        text: text
                    }
                ]
            }
        };

        try {
            const response = await axios.post<AzurePIIResponse>(url, requestBody, {
                headers: {
                    'Ocp-Apim-Subscription-Key': apiKey,
                    'Content-Type': 'application/json'
                }
            });

            console.log('Azure PII API Response:', JSON.stringify(response.data, null, 2));

            if (response.data.results && response.data.results.documents && response.data.results.documents.length > 0) {
                const entities = response.data.results.documents[0].entities || [];
                console.log(`Found ${entities.length} entities:`, entities.map(e => `${e.category}: "${e.text}"`));
                return entities;
            }

            return [];
        } catch (error: any) {
            console.error('Azure API Error:', error.response?.data || error.message);
            throw new Error(`Azure PII Detection failed: ${error.response?.data?.error?.message || error.message}`);
        }
    }

    // For large documents, split into chunks
    console.log(`Text is ${text.length} chars, splitting into chunks of ${CHUNK_SIZE}...`);

    for (let offset = 0; offset < text.length; offset += CHUNK_SIZE) {
        const chunk = text.substring(offset, offset + CHUNK_SIZE);
        const chunkNum = Math.floor(offset / CHUNK_SIZE) + 1;
        const totalChunks = Math.ceil(text.length / CHUNK_SIZE);

        console.log(`Processing chunk ${chunkNum}/${totalChunks} (${chunk.length} chars, offset ${offset})`);

        const requestBody = {
            kind: 'PiiEntityRecognition',
            parameters: {
                modelVersion: 'latest',
                domain: 'none',
                piiCategories: piiCategories
            },
            analysisInput: {
                documents: [
                    {
                        id: `chunk-${chunkNum}`,
                        language: language,
                        text: chunk
                    }
                ]
            }
        };

        try {
            const response = await axios.post<AzurePIIResponse>(url, requestBody, {
                headers: {
                    'Ocp-Apim-Subscription-Key': apiKey,
                    'Content-Type': 'application/json'
                }
            });

            if (response.data.results && response.data.results.documents && response.data.results.documents.length > 0) {
                const chunkEntities = response.data.results.documents[0].entities || [];

                // Adjust offsets to account for chunk position in full text
                const adjustedEntities = chunkEntities.map(entity => ({
                    ...entity,
                    offset: entity.offset + offset
                }));

                console.log(`Chunk ${chunkNum}: Found ${adjustedEntities.length} entities`);
                allEntities.push(...adjustedEntities);
            }
        } catch (error: any) {
            console.error(`Error processing chunk ${chunkNum}:`, error.response?.data || error.message);
            // Continue processing other chunks even if one fails
        }
    }


    console.log(`Total entities found across all chunks: ${allEntities.length}`);
    return allEntities;
}

// Custom regex-based PII detection for patterns Azure might miss
function detectCustomPatterns(text: string): PIIEntity[] {
    const customEntities: PIIEntity[] = [];

    // Date patterns (especially for DOB)
    // Matches: DD/MM/YYYY, MM/DD/YYYY, DD-MM-YYYY, DD.MM.YYYY, etc.
    // const datePatterns = [
    //     /\b(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})\b/g,  // 03/10/1988, 10-03-1988
    //     /\b(\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2})\b/g,   // 1988-03-10
    //     /\b(\d{1,2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[\s,]+\d{2,4})\b/gi,  // 15 December 1989, March 10, 1988
    //     /\b((?:January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\s+\d{1,2}[\s,]+\d{2,4})\b/gi,  // December 15, 1989
    // ];

    // datePatterns.forEach(pattern => {
    //     let match;
    //     while ((match = pattern.exec(text)) !== null) {
    //         customEntities.push({
    //             text: match[1],
    //             category: 'DateTime',
    //             offset: match.index,
    //             length: match[1].length,
    //             confidenceScore: 0.85
    //         });
    //     }
    // });

    // Credit card numbers with spaces or dashes
    // Matches: 4123 4567 8901 2345, 4123-4567-8901-2345
    const creditCardPattern = /\b(\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4})\b/g;
    let match;
    while ((match = creditCardPattern.exec(text)) !== null) {
        // Basic Luhn algorithm check to reduce false positives
        const digits = match[1].replace(/[\s\-]/g, '');
        if (digits.length === 16) {
            customEntities.push({
                text: match[1],
                category: 'CreditCardNumber',
                offset: match.index,
                length: match[1].length,
                confidenceScore: 0.75
            });
        }
    }

    // Swiss AHV/AVS number: XXX.XXXX.XXXX.XX
    const swissAHVPattern = /\b(\d{3}\.\d{4}\.\d{4}\.\d{2})\b/g;
    while ((match = swissAHVPattern.exec(text)) !== null) {
        customEntities.push({
            text: match[1],
            category: 'CHSocialSecurityNumber',
            offset: match.index,
            length: match[1].length,
            confidenceScore: 0.9
        });
    }

    // Phone numbers (various formats)
    const phonePattern = /\b(\+?\d{1,3}[\s\-]?\(?\d{2,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4})\b/g;
    while ((match = phonePattern.exec(text)) !== null) {
        if (match[1].replace(/[\s\-\(\)]/g, '').length >= 10) {
            customEntities.push({
                text: match[1],
                category: 'PhoneNumber',
                offset: match.index,
                length: match[1].length,
                confidenceScore: 0.7
            });
        }
    }

    console.log(`Custom regex found ${customEntities.length} additional patterns`);
    return customEntities;
}

// Merge and deduplicate entities from Azure and custom detection
function mergeEntities(azureEntities: PIIEntity[], customEntities: PIIEntity[]): PIIEntity[] {
    const merged = [...azureEntities];

    // Add custom entities that don't overlap with Azure entities
    customEntities.forEach(customEntity => {
        const overlaps = azureEntities.some(azureEntity => {
            const customStart = customEntity.offset;
            const customEnd = customEntity.offset + customEntity.length;
            const azureStart = azureEntity.offset;
            const azureEnd = azureEntity.offset + azureEntity.length;

            // Check if they overlap
            return (customStart < azureEnd && customEnd > azureStart);
        });

        if (!overlaps) {
            merged.push(customEntity);
        }
    });

    // Sort by offset
    merged.sort((a, b) => a.offset - b.offset);

    console.log(`Merged total: ${merged.length} entities (${azureEntities.length} from Azure + ${merged.length - azureEntities.length} from custom)`);
    return merged;
}

function convertEntitiesToRedactionCoordinates(
    entities: PIIEntity[],
    docIntelResult: DocIntelResponse['analyzeResult']
): RedactionCoordinate[] {
    const redactions: RedactionCoordinate[] = [];

    // Collect all words with their page indices
    const allWords: { word: DocIntelWord, pageIndex: number }[] = [];

    docIntelResult.pages.forEach((page, pageIndex) => {
        page.words.forEach(word => {
            allWords.push({ word, pageIndex });
        });
    });

    allWords.sort((a, b) => a.word.span.offset - b.word.span.offset);

    entities.forEach((entity) => {
        const entityStart = entity.offset;
        const entityEnd = entity.offset + entity.length;

        // Find words that overlap with this entity
        const relevantWords = allWords.filter(item => {
            const wordStart = item.word.span.offset;
            const wordEnd = wordStart + item.word.span.length;
            return (wordStart < entityEnd && wordEnd > entityStart);
        });

        relevantWords.forEach(item => {
            const azurePage = docIntelResult.pages[item.pageIndex];
            const polygon = item.word.polygon;

            // Calculate bounding box from polygon
            const xCoords = [polygon[0], polygon[2], polygon[4], polygon[6]];
            const yCoords = [polygon[1], polygon[3], polygon[5], polygon[7]];

            let minX = Math.min(...xCoords);
            let minY = Math.min(...yCoords);
            let maxX = Math.max(...xCoords);
            let maxY = Math.max(...yCoords);

            let x = minX;
            let y = minY;
            let w = maxX - minX;
            let h = maxY - minY;

            // Convert units to points (72 DPI)
            if (azurePage.unit === 'inch') {
                x *= 72;
                y *= 72;
                w *= 72;
                h *= 72;
            }
            // For pixel units, we don't convert as PyMuPDF will handle it

            redactions.push({
                pageIndex: item.pageIndex,
                x: x,
                y: y,
                width: w,
                height: h,
                text: entity.text,
                category: entity.category
            });
        });
    });

    console.log(`Converted ${entities.length} entities to ${redactions.length} redaction coordinates`);
    return redactions;
}

// Apply precise redactions based on Azure Doc Intel Polygons
async function redactPdfWithPyMuPDF(
    pdfBuffer: Buffer,
    redactions: RedactionCoordinate[],
    originalFilename: string
): Promise<Buffer> {
    const FASTAPI_URL = process.env.PDF_FAST_API_URL;

    try {
        console.log(`Sending PDF to FastAPI server at ${FASTAPI_URL}...`);
        console.log(`Total redactions: ${redactions.length}`);

        // Create form data
        const FormData = require('form-data');
        const formData = new FormData();

        // Append PDF file
        formData.append('file', pdfBuffer, {
            filename: originalFilename,
            contentType: 'application/pdf'
        });

        // Append redactions as JSON string
        formData.append('redactions', JSON.stringify(redactions));

        // Make request to FastAPI endpoint
        const response = await axios.post(`${FASTAPI_URL}/redact`, formData, {
            headers: {
                ...formData.getHeaders(),
            },
            responseType: 'arraybuffer', // Important: get binary data
            maxContentLength: Infinity,
            maxBodyLength: Infinity,
        });

        // Convert response to Buffer
        const redactedPdf = Buffer.from(response.data);
        console.log(`Redacted PDF size: ${redactedPdf.length} bytes`);

        return redactedPdf;

    } catch (error: any) {
        console.error('FastAPI redaction error:', error.message);
        if (error.response) {
            console.error('Response status:', error.response.status);
            console.error('Response data:', error.response.data?.toString());
        }

        throw new Error(`FastAPI redaction failed: ${error.message}`);
    }
}

export async function POST(req: NextRequest) {
    try {
        // Parse all uploaded files
        const { files: uploadedFiles } = await parseForm(req);

        if (!uploadedFiles || uploadedFiles.length === 0) {
            return NextResponse.json(
                { error: 'No files uploaded' },
                { status: 400 }
            );
        }

        console.log(`Processing ${uploadedFiles.length} PDF file(s)...`);

        // Get Azure Credentials
        const piiEndpoint = process.env.AZURE_PII_ENDPOINT;
        const piiApiKey = process.env.AZURE_PII_API_KEY;
        const docIntelEndpoint = process.env.AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT;
        const docIntelKey = process.env.AZURE_DOCUMENT_INTELLIGENCE_KEY;

        if (!docIntelEndpoint || !docIntelKey) {
            return NextResponse.json(
                { error: 'Azure Document Intelligence credentials not configured' },
                { status: 500 }
            );
        }

        if (!piiEndpoint || !piiApiKey) {
            return NextResponse.json(
                { error: 'Azure PII credentials not configured' },
                { status: 500 }
            );
        }

        // Process each PDF file to extract text and detect PII
        interface FileProcessingResult {
            file: UploadedFile;
            docIntelResult: DocIntelResponse['analyzeResult'];
            redactions: RedactionCoordinate[];
            pageCount: number;
            redactedBase64: string; // base64-encoded redacted PDF for this file
        }

        const fileResults: FileProcessingResult[] = [];
        let totalEntities = 0;

        for (let i = 0; i < uploadedFiles.length; i++) {
            const file = uploadedFiles[i];
            console.log(`\n=== Processing file ${i + 1}/${uploadedFiles.length}: ${file.originalFilename} ===`);

            // Step 1: Extract text & OCR with Azure Document Intelligence
            console.log(`File ${i + 1} - Step 1: Extracting text with Azure Document Intelligence...`);
            const docIntelResult = await extractTextWithAzureDocIntel(
                file.buffer,
                docIntelEndpoint,
                docIntelKey
            );
            const fullText = docIntelResult.content;
            console.log(`File ${i + 1} - Extracted ${fullText.length} characters`);

            // Step 2: Detect language
            console.log(`File ${i + 1} - Step 2: Detecting language...`);
            const language = await detectLanguage(fullText, piiEndpoint, piiApiKey);

            // Step 3: Detect PII with Azure
            console.log(`File ${i + 1} - Step 3: Detecting PII with Azure...`);
            const azureEntities = await detectPII(fullText, piiEndpoint, piiApiKey, language);
            console.log(`File ${i + 1} - Detected ${azureEntities.length} Azure PII entities`);

            // Step 4: Run custom regex patterns
            console.log(`File ${i + 1} - Step 4: Running custom regex patterns...`);
            const customEntities = detectCustomPatterns(fullText);

            // Step 5: Merge results
            console.log(`File ${i + 1} - Step 5: Merging results...`);
            const entities = mergeEntities(azureEntities, customEntities);
            console.log(`File ${i + 1} - Total ${entities.length} PII entities after merging`);

            totalEntities += entities.length;

            // Step 6: Convert entities to redaction coordinates
            const redactions = entities.length > 0
                ? convertEntitiesToRedactionCoordinates(entities, docIntelResult)
                : [];

            // Get page count from this PDF
            const pdfDoc = await PDFDocument.load(file.buffer);
            const pageCount = pdfDoc.getPageCount();

            // Redact this individual PDF and encode as base64
            const redactedPdfBuffer = await redactPdfWithPyMuPDF(
                file.buffer,
                redactions,
                file.originalFilename || `file-${i + 1}.pdf`
            );
            const redactedBase64 = redactedPdfBuffer.toString('base64');

            fileResults.push({
                file,
                docIntelResult,
                redactions,
                pageCount,
                redactedBase64
            });

            console.log(`File ${i + 1} - Found ${redactions.length} redaction coordinates across ${pageCount} pages`);
        }

        // If only one file and no PII, return original PDF info as JSON
        if (uploadedFiles.length === 1 && totalEntities === 0) {
            console.log('Single file with no PII detected, returning original PDF info');
            const originalBase64 = uploadedFiles[0].buffer.toString('base64');
            const responseBody = {
                files: [
                    {
                        filename: uploadedFiles[0].originalFilename,
                        redactedBase64: originalBase64,
                        pageCount: fileResults[0]?.pageCount || 0,
                        redactionsCount: 0
                    }
                ],
                combinedBase64: originalBase64,
                totalEntities: 0,
                totalRedactions: 0,
                filesMerged: uploadedFiles.length
            };
            return new NextResponse(JSON.stringify(responseBody), {
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // Merge all REDACTED PDFs into one (no need to redact again)
        console.log('\n=== Merging all REDACTED PDFs ===');
        const mergedPdf = await PDFDocument.create();
        let totalRedactionsCount = 0;

        for (let i = 0; i < fileResults.length; i++) {
            const result = fileResults[i];
            console.log(`Merging redacted file ${i + 1}: ${result.file.originalFilename} (${result.pageCount} pages)`);

            // Load the ALREADY REDACTED PDF (from redactedBase64)
            const redactedBuffer = Buffer.from(result.redactedBase64, 'base64');
            const redactedPdfDoc = await PDFDocument.load(redactedBuffer);
            const copiedPages = await mergedPdf.copyPages(redactedPdfDoc, redactedPdfDoc.getPageIndices());
            copiedPages.forEach(page => mergedPdf.addPage(page));

            totalRedactionsCount += result.redactions.length;
            console.log(`File ${i + 1}: Added ${result.pageCount} pages (already redacted with ${result.redactions.length} redactions)`);
        }

        console.log(`Merged PDF has ${mergedPdf.getPageCount()} total pages (all already redacted)`);

        // Save merged PDF to buffer
        const mergedPdfBytes = await mergedPdf.save();
        const combinedBase64 = Buffer.from(mergedPdfBytes).toString('base64');

        // Build response JSON
        const responseBody = {
            files: fileResults.map(fr => ({
                filename: fr.file.originalFilename,
                redactedBase64: fr.redactedBase64,
                pageCount: fr.pageCount,
                redactionsCount: fr.redactions.length
            })),
            combinedBase64,
            totalEntities,
            totalRedactions: totalRedactionsCount,
            filesMerged: uploadedFiles.length
        };

        return new NextResponse(JSON.stringify(responseBody), {
            status: 200,
            headers: {
                'Content-Type': 'application/json'
            }
        });

    } catch (error: any) {
        console.error('Error processing PDFs:', error.message, error.stack);

        return NextResponse.json(
            {
                error: 'Failed to process PDFs',
                details: error.message
            },
            { status: 500 }
        );
    }
}
