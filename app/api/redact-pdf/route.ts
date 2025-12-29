import { NextRequest, NextResponse } from 'next/server';
import axios from 'axios';
import { PDFDocument, rgb, degrees } from 'pdf-lib';
import { createServerClient } from '@supabase/ssr';
import { logInfo, logError, logWarn, logDebug } from '@/lib/logger';

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

// Style information from Azure Document Intelligence (for handwriting detection)
interface DocIntelStyle {
    isHandwritten?: boolean;
    spans: Array<{
        offset: number;
        length: number;
    }>;
    confidence: number;
}

interface DocIntelResponse {
    status: string;
    analyzeResult: {
        content: string;
        pages: DocIntelPage[];
        styles?: DocIntelStyle[];  // Contains handwriting detection info
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

// WHITELIST: Company Addresses (Never Redact)
// Includes both full addresses and individual components to handle cases where
// Azure Document Intelligence might split them into separate entities
const WHITELISTED_ADDRESSES = [
    // Full addresses with company names
    'Deutsche Grundstücksauktionen AG, Kurfürstendamm 65, 10707 Berlin',
    'Sächsische Grundstücksauktionen AG, Hohe Straße 12, 01069 Dresden',
    'WESTDEUTSCHE GRUNDSTÜCKSAUKTIONEN AG, Apostelnstraße 9, 50667 Köln',
    'Norddeutsche Grundstücksauktionen AG, Ernst-Barlach-Strasse 4, 18055 Rostock',
    'PLETTNER & BRECHT IMMOBILIEN GMBH, Kirschenallee 20, 14050 Berlin',

    // Individual address components (in case Azure splits them)
    'Kurfürstendamm 65, 10707 Berlin',
    'Kurfürstendamm 65',
    '10707 Berlin',

    'Hohe Straße 12, 01069 Dresden',
    'Hohe Straße 12',
    '01069 Dresden',

    'Apostelnstraße 9, 50667 Köln',
    'Apostelnstraße 9',
    '50667 Köln',

    'Ernst-Barlach-Strasse 4, 18055 Rostock',
    'Ernst-Barlach-Strasse 4',
    '18055 Rostock',

    'Kirschenallee 20, 14050 Berlin',
    'Kirschenallee 20',
    '14050 Berlin'
];

// WHITELIST: Organization Names (Never Redact)
// These company names should never be redacted
const WHITELISTED_ORGANIZATIONS = [
    'Deutsche Grundstücksauktionen AG',
    'Sächsische Grundstücksauktionen AG',
    'WESTDEUTSCHE GRUNDSTÜCKSAUKTIONEN AG',
    'Norddeutsche Grundstücksauktionen AG',
    'PLETTNER & BRECHT IMMOBILIEN GMBH'
];

// WHITELIST: German Role/Title Words (Not Personal Data)
// These words refer to roles, positions, or legal entities - NOT specific individuals
const WHITELISTED_ROLE_WORDS = [
    'Anwesenden',
    'Ausbauberechtigten',
    'Ausbauberechtigte',
    'Beauftragte',
    'Bevollmächtigten',
    'Erschienenen',
    'Erbengemeinschaft',
    'Fachmann',
    'teilende Eigentümer',
    'Eigentümer',
    'Eigentümern',
    'Notarin',
    'Notar',
    'Notaramtes',
    'Nutzungsberechtigten',
    'Sondernutzungsberechtigte',
    'Geschäftsführer',
    'Inhaber',
    'Miterben',
    'Mieter',
    'Mieterin',
    'Beteiligten',
    'Miteigentümer',
    'Teileigentümer',
    'Wohnungseigentümer',
    'Wohnungseigentümers',
    'Verwalters',
    'Verwalter',
    'Verwalterin',
    'Vermieter',
    'Vermieterin',
    'Versammlungsleiter',
    'Dritter',
    'Zahlender',
    'Vermieters',
    'Mieters',
    'Dritte',
    'Bewohner',
    'Gebäude',
    'Pächter',
    'Pächters',
    'Verpächter',
    'Verpächters',
    'Alleinpächter',
    'Nachfolgepächter',
    'Grundstück',
    'Betriebsnachfolger',
    'Landwirtschaftskammer',
    'Parteien',
    'Pachtvertrag',
    'Behörde',
    'Sachverständigen',
    'Vergleichswerte Endenergie',
    'Vergleichswerte',
    'Endenergie',
    'Endenergiebedarf',
    'Primärenergiebedarf',
    'Energieeffizienzklasse',
    'Energieausweis',
    'Energiebedarf',
    'Energiekennwert',
    'EEWärmeG',
    'EnEV',
    'Wärmeschutz',
    'Anforderungswert',
    'Ersatzmaßnahmen',
    'Erläuterungen',
    'Berechnungsverfahren',
    'Pflichtangabe',
    'Immobilienanzeigen',
    'Angaben zum',
    'Dritten',
    'behindertengerechte',
    'Erfüllungsgehilfen',
    'Beauftragten'
];

// Helper function to parse form data for multiple files
async function parseForm(req: NextRequest): Promise<{ fields: any; files: UploadedFile[] }> {
    const formData = await req.formData();
    const filesArray = formData.getAll('files[]') as File[];

    const fields: Record<string, string> = {};
    for (const [key, value] of formData.entries()) {
        if (!(value instanceof File)) {
            fields[key] = value as string;
        }
    }

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
        fields: fields,
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
        'DateOfBirth',
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
    let match;

    // Job titles/occupations - German and English
    const jobTitles = [
        // German jobs
        'Krankenpfleger', 'Krankenschwester', 'Arzt', 'Ärztin',
        'Ingenieur', 'Ingenieurin', 'Lehrer', 'Lehrerin',
        'Buchhalter', 'Buchhalterin', 'Programmierer', 'Programmiererin',
        'Manager', 'Managerin', 'Verkäufer', 'Verkäuferin',
        // English jobs
        'Nurse', 'Doctor', 'Engineer', 'Teacher', 'Accountant',
        'Programmer', 'Manager', 'Salesperson',
        // Add more as needed
    ];

    const jobPattern = new RegExp(`\\b(${jobTitles.join('|')})\\b`, 'gi');
    while ((match = jobPattern.exec(text)) !== null) {
        customEntities.push({
            text: match[0],
            category: 'Occupation',
            offset: match.index,
            length: match[0].length,
            confidenceScore: 0.85
        });
    }

    const jobContextPattern = /(?:Beruf|Occupation|Job|Tätigkeit)[:\s\n]*([A-Za-zäöüÄÖÜß0-9\s\-]+?)(?:\n|,|\.|\||$)/gi;
    while ((match = jobContextPattern.exec(text)) !== null) {
        customEntities.push({
            text: match[1].trim(),
            category: 'Occupation',
            offset: match.index + match[0].indexOf(match[1]),
            length: match[1].trim().length,
            confidenceScore: 0.80
        });
    }

    const germanDOBPattern = /(?:Geb\s*\.?\s*-?\s*Datum|Geb\.|Geboren|Geburtsdatum)(?:\s+am)?[:\s\n]+(\d{1,2}[\.\/\-]\d{1,2}[\.\/\-]\d{2,4})/gi;
    while ((match = germanDOBPattern.exec(text)) !== null) {
        customEntities.push({
            text: match[1],
            category: 'DateOfBirth',
            offset: match.index + match[0].indexOf(match[1]),
            length: match[1].length,
            confidenceScore: 0.90
        });
    }

    const germanDOBFallback = /\b(?:Geb\s*\.?\s*-?\s*Datum|Geboren)\b[^\d]{0,50}(\d{1,2}\.\d{1,2}\.\d{2,4})/gi;
    while ((match = germanDOBFallback.exec(text)) !== null) {
        customEntities.push({
            text: match[1],
            category: 'DateOfBirth',
            offset: match.index + match[0].indexOf(match[1]),
            length: match[1].length,
            confidenceScore: 0.85
        });
    }

    // Pattern D: Specific pattern for "Geb.-Datum" in tables
    // Handles cases where date is on next line or far away
    const gebDatumTable = /Geb\s*\.\s*-\s*Datum[^\d]{0,100}(\d{2}\.\d{2}\.\d{4})/gi;
    while ((match = gebDatumTable.exec(text)) !== null) {
        customEntities.push({
            text: match[1],
            category: 'DateOfBirth',
            offset: match.index + match[0].indexOf(match[1]),
            length: match[1].length,
            confidenceScore: 0.85
        });
    }

    const germanDOBTextMonth = /(?:geboren|Geb\.|Geburtsdatum)\s+am\s+(\d{1,2}\.\s+(?:Januar|Februar|März|April|Mai|Juni|Juli|August|September|Oktober|November|Dezember)\s+\d{4})/gi;
    while ((match = germanDOBTextMonth.exec(text)) !== null) {
        customEntities.push({
            text: match[1],
            category: 'DateOfBirth',
            offset: match.index + match[0].indexOf(match[1]),
            length: match[1].length,
            confidenceScore: 0.90
        });
    }

    // Debug: Check if BLZ text exists in the document
    if (text.includes('Blz') || text.includes('BLZ')) {
        const blzIndex = text.toLowerCase().indexOf('blz');
        const start = Math.max(0, blzIndex - 20);
        const end = Math.min(text.length, blzIndex + 100);
        const context = text.substring(start, end);
        console.log('🔍 DEBUG: BLZ TEXT FOUND IN DOCUMENT');
        console.log('Position:', blzIndex);
        console.log('Context (raw):', JSON.stringify(context));
        console.log('Context (visible):', context);

        // Show character codes to identify hidden characters
        const detailSection = text.substring(blzIndex, Math.min(text.length, blzIndex + 50));
        console.log('Character codes:', detailSection.split('').map((c, i) =>
            `${i}: '${c}' (code: ${c.charCodeAt(0)})`
        ).join(', '));
    }

    const blzPattern = /(?:BLZ|Blz)\s*\.?\s*:?\s*(\d{1,3})\s+(\d{1,3})\s+(\d{1,5})/gi;
    let blzMatchCount = 0;
    while ((match = blzPattern.exec(text)) !== null) {
        blzMatchCount++;
        const fullNumber = match[1] + match[2] + match[3]; // Combine: "100" + "700" + "24"
        console.log(`🔍 DEBUG: BLZ MATCH #${blzMatchCount} FOUND:`, {
            fullMatch: match[0],
            capturedGroups: [match[1], match[2], match[3]],
            combinedNumber: fullNumber,
            offset: match.index
        });
        customEntities.push({
            text: fullNumber,
            category: 'DEBankCode',
            offset: match.index + match[0].indexOf(match[1]),
            length: match[0].length - match[0].indexOf(match[1]),
            confidenceScore: 0.90
        });
    }

    if (blzMatchCount === 0 && (text.includes('Blz') || text.includes('BLZ'))) {
        console.log('⚠️ DEBUG: BLZ text found but pattern did NOT match!');
    }

    const bicPattern = /\b([A-Z]{4}\s?[A-Z]{2}\s?[A-Z0-9]\s?[A-Z0-9]\s?(?:[A-Z0-9]{3})?)\b/g;
    while ((match = bicPattern.exec(text)) !== null) {
        const bicWithSpaces = match[1];
        const bicClean = bicWithSpaces.replace(/\s/g, '');

        if (bicClean.length === 8 || bicClean.length === 11) {
            customEntities.push({
                text: bicWithSpaces,
                category: 'SWIFTCode',
                offset: match.index,
                length: bicWithSpaces.length,
                confidenceScore: 0.85
            });
        }
    }

    // BIC with keyword - captures only the code value, not the prefix
    const bicWithKeywordPattern = /(?:BIC|Bic)\s*\.?\s*:?\s*([A-Z]{4}\s?[A-Z]{2}\s?[A-Z0-9]\s?[A-Z0-9]\s?(?:[A-Z0-9]{3})?)/gi;
    while ((match = bicWithKeywordPattern.exec(text)) !== null) {
        const bicWithSpaces = match[1]; // Capture group 1 = just the code
        const bicClean = bicWithSpaces.replace(/\s/g, '');

        if (bicClean.length === 8 || bicClean.length === 11) {
            customEntities.push({
                text: bicWithSpaces, // Only the code, not "BIC:"
                category: 'SWIFTCode',
                offset: match.index + match[0].indexOf(match[1]), // Offset of the code only
                length: bicWithSpaces.length, // Length of the code only
                confidenceScore: 0.90 // Higher confidence because it has the keyword
            });
        }
    }


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
        const phoneCandidate = match[1];
        const digitsOnly = phoneCandidate.replace(/[\s\-\(\)\n\r]/g, '');

        // Must have at least 10 digits to be a phone number
        if (digitsOnly.length < 10) {
            continue;
        }
        const isLikelyEnergyScale = (
            // Contains newlines (common in energy scale OCR output)
            (phoneCandidate.includes('\n') || phoneCandidate.includes('\r')) &&
            // All "digit groups" are 1-3 digits (energy scale numbers are small)
            digitsOnly.match(/^\d{1,3}(\d{1,3})*$/) &&
            // Check if it looks like energy scale pattern (incrementing small numbers)
            /^(25|50|75|100|125|150|175|200|225|250)/.test(digitsOnly)
        );

        // Also check for space-separated small numbers (like "150 175 200 225")
        const spaceSeparatedNumbers = phoneCandidate.replace(/[\n\r]/g, ' ').split(/\s+/).filter(s => s.length > 0);
        const allSmallNumbers = spaceSeparatedNumbers.every(num => {
            const parsed = parseInt(num, 10);
            return !isNaN(parsed) && parsed <= 300;
        });
        const hasEnoughSmallNumbers = spaceSeparatedNumbers.length >= 3 && allSmallNumbers;

        if (isLikelyEnergyScale || hasEnoughSmallNumbers) {
            console.log(`Phone pattern SKIPPED (likely energy scale): "${phoneCandidate.replace(/\n/g, '\\n')}"`);
            continue;
        }

        customEntities.push({
            text: phoneCandidate,
            category: 'PhoneNumber',
            offset: match.index,
            length: phoneCandidate.length,
            confidenceScore: 0.7
        });
    }

    //German Tax ID (USt-ID-Nr./VAT ID): DE followed by 9 digits
    // Format: DE123456789 or DE 123 456 789 or DE 123456789
    const germanTaxIdPattern = /\b(DE\s*\d{3}\s*\d{3}\s*\d{3})\b/gi;
    while ((match = germanTaxIdPattern.exec(text)) !== null) {
        customEntities.push({
            text: match[1],
            category: 'DEVatNumber',
            offset: match.index,
            length: match[1].length,
            confidenceScore: 0.95
        });
    }

    // Also catch DE followe dby 9 digits without spaces
    const germanTaxIdPattern2 = /\b(DE\d{9})\b/gi;
    while ((match = germanTaxIdPattern2.exec(text)) !== null) {
        // Avoid duplicates if already matched above
        const alreadyExists = customEntities.some(e =>
            e.offset === match!.index && e.category === 'DEVatNumber'
        );
        if (!alreadyExists) {
            customEntities.push({
                text: match[1],
                category: 'DEVatNumber',
                offset: match.index,
                length: match[1].length,
                confidenceScore: 0.95
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
        console.log(`\n--- Processing custom entity: [${customEntity.category}] "${customEntity.text}" at ${customEntity.offset}-${customEntity.offset + customEntity.length}`);

        const overlaps = azureEntities.some(azureEntity => {
            const customStart = customEntity.offset;
            const customEnd = customEntity.offset + customEntity.length;
            const azureStart = azureEntity.offset;
            const azureEnd = azureEntity.offset + azureEntity.length;
            const hasOverlap = (customStart < azureEnd && customEnd > azureStart);

            if (hasOverlap) {
                console.log(`  OVERLAP with Azure: [${azureEntity.category}] "${azureEntity.text}" at ${azureStart}-${azureEnd}`);
            }
            if (hasOverlap && customEntity.category === 'Occupation' && azureEntity.category === 'Organization') {
                // Remove the Azure Organization entity from merged array
                const indexToRemove = merged.findIndex(e =>
                    e.offset === azureEntity.offset &&
                    e.length === azureEntity.length &&
                    e.category === 'Organization'
                );
                if (indexToRemove !== -1) {
                    merged.splice(indexToRemove, 1);
                }
                return false; // No overlap, allow custom entity to be added
            }

            // BLZ (DEBankCode) takes priority over PhoneNumber
            if (hasOverlap && customEntity.category === 'DEBankCode' && azureEntity.category === 'PhoneNumber') {
                // Remove the Azure PhoneNumber entity from merged array
                const indexToRemove = merged.findIndex(e =>
                    e.offset === azureEntity.offset &&
                    e.length === azureEntity.length &&
                    e.category === 'PhoneNumber'
                );
                if (indexToRemove !== -1) {
                    merged.splice(indexToRemove, 1);
                }
                return false; // No overlap, allow custom BLZ entity to be added
            }

            // BLZ (DEBankCode) takes priority over IBAN
            if (hasOverlap && customEntity.category === 'DEBankCode' && azureEntity.category === 'InternationalBankingAccountNumber') {
                const indexToRemove = merged.findIndex(e =>
                    e.offset === azureEntity.offset &&
                    e.length === azureEntity.length &&
                    e.category === 'InternationalBankingAccountNumber'
                );
                if (indexToRemove !== -1) {
                    merged.splice(indexToRemove, 1);
                }
                return false; // No overlap, allow custom BLZ entity to be added
            }

            return hasOverlap;
        });

        if (!overlaps) {
            merged.push(customEntity);
            console.log(`  Added custom entity to merged array`);
        } else {
            console.log(` Skipped custom entity (overlaps with Azure entity)`);
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

            // Add padding to ensure the redaction fully covers the text
            // This prevents text from being visible/copyable at the edges
            const PADDING_INCH = 0.02; // ~1.5 points of padding
            minX = Math.max(0, minX - PADDING_INCH);
            minY = Math.max(0, minY - PADDING_INCH);
            maxX = maxX + PADDING_INCH;
            maxY = maxY + PADDING_INCH;


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

// Detect signatures using YOLOS AI model via FastAPI
async function detectSignaturesWithYOLO(
    pdfBuffer: Buffer,
    existingSignatures: RedactionCoordinate[] = []
): Promise<RedactionCoordinate[]> {
    const FASTAPI_URL = process.env.PDF_FAST_API_URL;

    try {
        console.log('[YOLO] Calling AI signature detection endpoint...');

        const FormData = require('form-data');
        const formData = new FormData();

        formData.append('file', pdfBuffer, {
            filename: 'document.pdf',
            contentType: 'application/pdf'
        });
        formData.append('existing_signatures', JSON.stringify(existingSignatures));

        const response = await axios.post(`${FASTAPI_URL}/detect-signatures`, formData, {
            headers: {
                ...formData.getHeaders(),
            },
            timeout: 300000, // 5 minute timeout for AI processing on large PDFs
        });

        if (response.data.success && response.data.signatures) {
            console.log(`[YOLO] Found ${response.data.count} signatures`);
            return response.data.signatures.map((sig: any) => ({
                pageIndex: sig.pageIndex,
                x: sig.x,
                y: sig.y,
                width: sig.width,
                height: sig.height,
                text: sig.text || '[Signature]',
                category: 'Signature'
            }));
        }

        return [];
    } catch (error: any) {
        console.error('[YOLO] Signature detection failed:', error.message);
        // Return empty array on failure - don't break the main flow
        return [];
    }
}


// Detect signatures from Azure Document Intelligence styles collection
function detectSignaturesFromStyles(
    docIntelResult: DocIntelResponse['analyzeResult']
): RedactionCoordinate[] {
    const signatures: RedactionCoordinate[] = [];
    const styles = docIntelResult.styles || [];
    const pages = docIntelResult.pages || [];
    const content = docIntelResult.content || '';

    // Signature-related labels
    const signatureLabels = [
        'unterschrift',
        'unterschriften',
        'signature',
        'signatures',
        'signed',
        'datum/unterschrift',
        'unterzeichner',
        'unterzeichnet',
        'gezeichnet',
        'gez.',
        'i.a.',
        'ppa.',
        'protokollführer',
        'zeuge'
    ];

    // Patterns for common form field text to exclude (broader list to prevent over-redaction)
    const formFieldPatterns = [
        /^[\d\s.,€$%]+$/,           // Pure numbers/currency
        /^\d{1,2}[.,]\d{2}[.,]\d{4}$/, // Dates
        /^[xX✓✗]$/,                   // Checkmarks
        /^ja$/i, /^nein$/i,           // Yes/No
        /^EUR?$/i,                    // Currency symbols
        /^\d{5}$/,                    // Postal codes
        /^\d+[.,]?\d*\s*kWh/i,        // Energy values (kWh)
        /^\d+[.,]?\d*\s*m[²2³3]/i,    // Area measurements (m², m³)
        /^\d+[.,]?\d*\s*%$/,          // Percentage values
        /^[A-H]\+?$/i,                // Energy efficiency ratings (A+, B, C, etc.)
        /^>?\d+$/,                    // Numbers with optional > (like >250)
        /^\d{1,3}$/,                  // Short numbers (1-3 digits)
        /^[A-Z]{1,5}$/,               // Short letter codes
    ];

    console.log(`Checking ${styles.length} styles for handwritten content...`);

    // Find all handwritten styles
    const handwrittenStyles = styles.filter(style => style.isHandwritten === true);
    console.log(`Found ${handwrittenStyles.length} handwritten regions`);

    // Process handwritten content from Azure styles
    for (const style of handwrittenStyles) {
        for (const span of style.spans) {
            // Extract the handwritten text
            const handwrittenText = content.substring(span.offset, span.offset + span.length).trim();

            // Check context for signature labels FIRST (before length filter)
            const contextRadius = 150;
            const contextStart = Math.max(0, span.offset - contextRadius);
            const contextEnd = Math.min(content.length, span.offset + span.length + contextRadius);
            const context = content.substring(contextStart, contextEnd).toLowerCase();
            const isNearSignatureLabel = signatureLabels.some(label => context.includes(label));

            // Filter 1: Length filter - stricter for non-signature-adjacent text
            // Allow 2+ chars when near signature labels, 3+ chars otherwise
            const minLength = isNearSignatureLabel ? 2 : 3;
            if (handwrittenText.length < minLength) {
                console.log(`Handwritten text: "${handwrittenText}" - SKIPPED (too short, ${handwrittenText.length} chars, min=${minLength}, nearLabel=${isNearSignatureLabel})`);
                continue;
            }

            // Filter 2: Skip common form field patterns
            const isFormField = formFieldPatterns.some(pattern => pattern.test(handwrittenText));
            if (isFormField) {
                console.log(`Handwritten text: "${handwrittenText}" - SKIPPED (matches form field pattern)`);
                continue;
            }

            console.log(`Handwritten text: "${handwrittenText.substring(0, 50)}..." (offset: ${span.offset}, length: ${span.length})`)

            // Find words that match this span
            const matchingWords: Array<{ word: DocIntelWord; pageIndex: number; pageHeight: number; pageUnit: string }> = [];

            for (let pageIdx = 0; pageIdx < pages.length; pageIdx++) {
                const page = pages[pageIdx];
                for (const word of page.words) {
                    // Check if word's span overlaps with handwritten span
                    const wordStart = word.span.offset;
                    const wordEnd = word.span.offset + word.span.length;
                    const spanStart = span.offset;
                    const spanEnd = span.offset + span.length;

                    if (wordStart < spanEnd && wordEnd > spanStart) {
                        matchingWords.push({
                            word,
                            pageIndex: pageIdx,
                            pageHeight: page.height,
                            pageUnit: page.unit || 'inch'
                        });
                    }
                }
            }

            if (matchingWords.length === 0) {
                console.log(`  No matching words found for handwritten span`);
                continue;
            }

            // SPATIAL PROXIMITY CHECK: Look for signature labels on same page near this handwritten text
            const handwrittenPageIdx = matchingWords[0].pageIndex;
            const handwrittenY = (matchingWords[0].word.polygon[1] + matchingWords[0].word.polygon[5]) / 2;
            const handwrittenX = (matchingWords[0].word.polygon[0] + matchingWords[0].word.polygon[2]) / 2;

            let isNearLabelSpatially = false;
            const samePage = pages[handwrittenPageIdx];
            if (samePage) {
                for (const pageWord of samePage.words) {
                    const wordText = pageWord.content.toLowerCase();
                    const isLabel = signatureLabels.some(label => wordText.includes(label));
                    if (isLabel) {
                        const labelY = (pageWord.polygon[1] + pageWord.polygon[5]) / 2;
                        const labelX = (pageWord.polygon[0] + pageWord.polygon[2]) / 2;

                        // Check if handwritten text is within 2 inches vertically, 4 inches horizontally
                        const yDistance = Math.abs(handwrittenY - labelY);
                        const xDistance = Math.abs(handwrittenX - labelX);

                        if (yDistance < 2.0 && xDistance < 4.0) {
                            isNearLabelSpatially = true;
                            console.log(`  Spatial match: "${handwrittenText}" near label "${pageWord.content}" (yDist=${yDistance.toFixed(2)}, xDist=${xDistance.toFixed(2)})`);
                            break;
                        }
                    }
                }
            }

            // Combine text-based and spatial proximity
            const isNearLabel = isNearSignatureLabel || isNearLabelSpatially;

            // Re-check min length with spatial proximity
            if (!isNearSignatureLabel && isNearLabelSpatially && handwrittenText.length >= 2) {
                console.log(`  Spatial proximity allows 2-char detection for "${handwrittenText}"`);
            } else if (handwrittenText.length < (isNearLabel ? 2 : 3)) {
                console.log(`  SKIPPED after spatial check (${handwrittenText.length} chars, nearLabel=${isNearLabel})`);
                continue;
            }

            // Check if this handwritten region is a signature
            // Criteria 2: Check if in bottom 40% of page
            const avgWordY = matchingWords.reduce((sum, mw) => {
                const y1 = mw.word.polygon[1];
                const y3 = mw.word.polygon[5];
                return sum + (y1 + y3) / 2;
            }, 0) / matchingWords.length;

            const pageHeight = matchingWords[0].pageHeight;
            const isInBottomPortion = avgWordY > pageHeight * 0.75; // Changed from 0.6 to 0.75 (bottom 25%)

            console.log(`  - Near label (text/spatial): ${isNearLabel}, In bottom 25%: ${isInBottomPortion} (y=${avgWordY.toFixed(1)}, height=${pageHeight})`);

            // STRICTER RULE: Only accept as signature
            const isLikelySignature = isNearLabel || (isInBottomPortion && handwrittenText.length >= 5);

            if (isLikelySignature) {

                // Calculate bounding box for all matching words
                let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
                let signaturePageIndex = matchingWords[0].pageIndex;

                for (const mw of matchingWords) {
                    const polygon = mw.word.polygon;
                    console.log(`    Word: "${mw.word.content}" polygon: [${polygon.map(p => p.toFixed(2)).join(', ')}]`);
                    // polygon: [x1, y1, x2, y2, x3, y3, x4, y4]
                    for (let i = 0; i < polygon.length; i += 2) {
                        minX = Math.min(minX, polygon[i]);
                        maxX = Math.max(maxX, polygon[i]);
                    }
                    for (let i = 1; i < polygon.length; i += 2) {
                        minY = Math.min(minY, polygon[i]);
                        maxY = Math.max(maxY, polygon[i]);
                    }
                }

                // Add padding around signature (in page units)
                const padding = 0.05; // ~3.6 points at 72 DPI
                minX = Math.max(0, minX - padding);
                minY = Math.max(0, minY - padding);
                maxX = maxX + padding;
                maxY = maxY + padding;

                // Convert from inches to points if needed (72 points per inch)
                const pageUnit = matchingWords[0].pageUnit;
                if (pageUnit === 'inch') {
                    minX *= 72;
                    minY *= 72;
                    maxX *= 72;
                    maxY *= 72;
                }

                const width = maxX - minX;
                const height = maxY - minY;

                signatures.push({
                    pageIndex: signaturePageIndex,
                    x: minX,
                    y: minY,
                    width: width,
                    height: height,
                    text: `[Signature: ${handwrittenText.substring(0, 30)}...]`,
                    category: 'Signature'
                });

                console.log(`  Added signature redaction: page ${signaturePageIndex}, (${minX.toFixed(1)}, ${minY.toFixed(1)}) ${width.toFixed(1)}x${height.toFixed(1)} (converted from ${pageUnit})`);
            } else {
                console.log(`  ✗ Not a signature (handwritten form field)`);
            }
        }
    }

    // FALLBACK METHOD: Look for content near signature labels even if not marked as handwritten
    // This catches signatures that Azure doesn't recognize as handwritten
    if (signatures.length === 0) {
        console.log(`\nFallback: Searching for text near signature labels (no handwritten content detected)...`);

        for (let pageIdx = 0; pageIdx < pages.length; pageIdx++) {
            const page = pages[pageIdx];
            const pageHeight = page.height;

            for (const word of page.words) {
                const wordText = word.content.toLowerCase();

                // Look for signature label keywords
                const isSignatureLabel = signatureLabels.some(label =>
                    wordText.includes(label) || (label.length > 4 && wordText.includes(label.substring(0, 5)))
                );

                if (isSignatureLabel && wordText.length > 3) {
                    const labelY = (word.polygon[1] + word.polygon[5]) / 2;
                    const labelX = (word.polygon[0] + word.polygon[2]) / 2;

                    // Only process if label is in bottom 50% of page
                    if (labelY < pageHeight * 0.5) continue;

                    console.log(`  Found signature label: "${word.content}" at y=${labelY.toFixed(2)}`);

                    // Find text below this label (potential signature)
                    for (const nearbyWord of page.words) {
                        if (nearbyWord === word) continue;

                        const nearbyY = (nearbyWord.polygon[1] + nearbyWord.polygon[5]) / 2;
                        const nearbyX = (nearbyWord.polygon[0] + nearbyWord.polygon[2]) / 2;

                        // Check if word is below the label (within 1 inch) and horizontally nearby
                        const isBelow = nearbyY > labelY && (nearbyY - labelY) < 1.0;
                        const isBeside = Math.abs(nearbyX - labelX) < 3.0;

                        if (isBelow && isBeside) {
                            const nearbyText = nearbyWord.content;

                            // Check if this looks like a signature
                            const isCommonWord = /^(ja|nein|oder|und|der|die|das|nicht|bitte|von|zu)$/i.test(nearbyText);
                            const hasLetters = /[a-zA-ZäöüÄÖÜß]{3,}/.test(nearbyText);

                            // Check if already detected
                            const alreadyDetected = signatures.some(sig =>
                                sig.pageIndex === pageIdx &&
                                Math.abs(sig.x - nearbyWord.polygon[0] * 72) < 50 &&
                                Math.abs(sig.y - nearbyWord.polygon[1] * 72) < 50
                            );

                            if (!isCommonWord && hasLetters && !alreadyDetected && nearbyText.length >= 3) {
                                console.log(`    Fallback found potential signature: "${nearbyText}"`);

                                const polygon = nearbyWord.polygon;
                                let x = Math.min(polygon[0], polygon[6]) - 0.1;
                                let y = Math.min(polygon[1], polygon[3]) - 0.1;
                                let w = Math.max(polygon[2], polygon[4]) - x + 0.2;
                                let h = Math.max(polygon[5], polygon[7]) - y + 0.2;

                                // Convert units if needed
                                if (page.unit === 'inch') {
                                    x *= 72;
                                    y *= 72;
                                    w *= 72;
                                    h *= 72;
                                }

                                if (w > 20 && h > 10) {
                                    signatures.push({
                                        pageIndex: pageIdx,
                                        x, y, width: w, height: h,
                                        text: `[Signature (fallback): ${nearbyText}]`,
                                        category: 'Signature'
                                    });
                                    console.log(`    Added fallback signature: (${x.toFixed(1)}, ${y.toFixed(1)}) ${w.toFixed(1)}x${h.toFixed(1)}`);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    console.log(`Total signatures detected: ${signatures.length}`);
    return signatures;
}

// WHITELIST CHECKING FUNCTION
/**
 * Checks if an entity text matches any whitelisted address or role word
 * @param entityText - The text of the entity to check
 * @param category - The category of the entity (optional, for logging)
 * @returns true if the entity should be excluded (is whitelisted), false otherwise
 */
function isWhitelisted(entityText: string, category?: string): boolean {
    // Normalize the entity text for comparison
    const normalizeText = (text: string): string => {
        return text.toLowerCase()
            .replace(/ß/g, 'ss')
            .replace(/ä/g, 'ae')
            .replace(/ö/g, 'oe')
            .replace(/ü/g, 'ue')
            .replace(/str\./gi, 'strasse')
            .replace(/\bstr\b/gi, 'strasse')
            .replace(/[\r\n,\-\.]/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();
    };

    const normalizedEntity = normalizeText(entityText);

    // Check against whitelisted role words (exact word match or as part of entity)
    for (const roleWord of WHITELISTED_ROLE_WORDS) {
        const normalizedRole = normalizeText(roleWord);

        // Check if the entity is exactly this role word
        if (normalizedEntity === normalizedRole) {
            console.log(`✓ WHITELIST MATCH (Role): "${entityText}" matches "${roleWord}"`);
            return true;
        }

        // Check if the entity is just this role word (as a standalone word)
        const entityWords = normalizedEntity.split(' ');
        if (entityWords.length === 1 && entityWords[0] === normalizedRole) {
            console.log(`✓ WHITELIST MATCH (Role): "${entityText}" matches "${roleWord}"`);
            return true;
        }

        if (entityWords.includes(normalizedRole)) {
            return true;
        }

        const roleWordRegex = new RegExp(`\\b${normalizedRole}\\b`, 'i');
        if (roleWordRegex.test(normalizedEntity)) {
            return true;
        }
    }

    // Check against whitelisted organizations (exact or fuzzy match)
    for (const org of WHITELISTED_ORGANIZATIONS) {
        const normalizedOrg = normalizeText(org);

        // Exact match
        if (normalizedEntity === normalizedOrg) {
            console.log(`✓ WHITELIST MATCH (Organization): \"${entityText}\" matches \"${org}\"`);
            return true;
        }

        // Fuzzy match (for OCR errors)
        if (normalizedEntity.includes(normalizedOrg) || normalizedOrg.includes(normalizedEntity)) {
            console.log(`✓ WHITELIST MATCH (Organization Substring): \"${entityText}\" matches \"${org}\"`);
            return true;
        }
    }

    // Check against whitelisted addresses (fuzzy matching for OCR errors)
    for (const address of WHITELISTED_ADDRESSES) {
        const normalizedAddress = normalizeText(address);

        // Method 1: Direct substring match
        if (normalizedEntity.includes(normalizedAddress) ||
            normalizedAddress.includes(normalizedEntity)) {
            console.log(`✓ WHITELIST MATCH (Address Substring): "${entityText}" matches "${address}"`);
            return true;
        }

        // Method 2: Check if entity contains significant parts of the address
        const addressParts = normalizedAddress.split(' ').filter(p => p.length > 2);
        const entityParts = normalizedEntity.split(' ').filter(p => p.length > 2);

        const matchingParts = addressParts.filter(part =>
            entityParts.some(entityPart => entityPart === part || entityPart.includes(part) || part.includes(entityPart))
        );

        // If more than 50% of address parts match and at least 2 parts match
        const matchRatio = matchingParts.length / addressParts.length;
        if (matchRatio >= 0.5 && matchingParts.length >= 2) {
            console.log(`✓ WHITELIST MATCH (Address Parts): "${entityText}" matches "${address}" (${matchingParts.length}/${addressParts.length} parts)`);
            return true;
        }
    }

    return false;
}

export async function POST(req: NextRequest) {
    const requestId = `req_${Date.now()}_${Math.random().toString(36).substring(7)}`;

    logInfo('PDF redaction request received', { request_id: requestId });

    try {
        // Dual authentication: Supabase session OR bearer token

        // First, check if user is authenticated via Supabase (logged-in users)
        const supabase = createServerClient(
            process.env.NEXT_PUBLIC_SUPABASE_URL!,
            process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
            {
                cookies: {
                    getAll() {
                        return req.cookies.getAll()
                    },
                    setAll(cookiesToSet) {
                        // Not needed for API routes
                    },
                },
            }
        );

        const { data: { user } } = await supabase.auth.getUser();

        // If user is logged in via Supabase, allow the request
        const isAuthenticatedUser = !!user;

        if (isAuthenticatedUser) {
            logInfo('Request authenticated via Supabase', {
                request_id: requestId,
                user_id: user.id
            });
        }

        // If NOT logged in, check for bearer token (for n8n and external APIs)
        if (!isAuthenticatedUser) {
            const authHeader = req.headers.get('authorization');
            const expectedToken = process.env.API_BEARER_TOKEN;

            // If bearer token is configured, require it for non-logged-in users
            if (expectedToken) {
                if (!authHeader) {
                    logWarn('Authentication failed - no credentials provided', { request_id: requestId });
                    return NextResponse.json(
                        { error: 'Authentication required. Please login or provide a valid bearer token.' },
                        { status: 401 }
                    );
                }

                if (!authHeader.startsWith('Bearer ')) {
                    logWarn('Authentication failed - invalid bearer token format', { request_id: requestId });
                    return NextResponse.json(
                        { error: 'Invalid authorization header. Expected Bearer token.' },
                        { status: 401 }
                    );
                }

                const token = authHeader.replace('Bearer ', '');
                if (token !== expectedToken) {
                    logWarn('Authentication failed - invalid bearer token', { request_id: requestId });
                    return NextResponse.json(
                        { error: 'Invalid bearer token' },
                        { status: 401 }
                    );
                }

                logInfo('Request authenticated via Bearer token', { request_id: requestId });
            }
        }

        // Parse all uploaded files
        const { files: uploadedFiles, fields } = await parseForm(req);
        const excludeAddress = fields.excludeAddress as string | null;

        logInfo('Files uploaded', {
            request_id: requestId,
            file_count: uploadedFiles.length,
            exclude_address: excludeAddress || 'none'
        });

        if (!uploadedFiles || uploadedFiles.length === 0) {
            logWarn('No files uploaded in request', { request_id: requestId });
            return NextResponse.json(
                { error: 'No files uploaded' },
                { status: 400 }
            );
        }

        logInfo('Processing PDF files', {
            request_id: requestId,
            file_count: uploadedFiles.length
        });

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

            const gebDatumIndex = fullText.indexOf('Geb.-Datum');
            if (gebDatumIndex !== -1) {
                console.log('\n=== DEBUG: Text around Geb.-Datum ===');
                console.log('Position:', gebDatumIndex);
                // Show 200 characters before and after
                const start = Math.max(0, gebDatumIndex - 50);
                const end = Math.min(fullText.length, gebDatumIndex + 200);
                const snippet = fullText.substring(start, end);
                console.log('Text snippet:', JSON.stringify(snippet));
                console.log('Character codes:', snippet.split('').map((c, i) => `${i}: '${c}' (${c.charCodeAt(0)})`).join('\n'));
            }

            // Step 3: Detect PII with Azure
            console.log(`File ${i + 1} - Step 3: Detecting PII with Azure...`);
            const azureEntities = await detectPII(fullText, piiEndpoint, piiApiKey, language);
            console.log(`File ${i + 1} - Detected ${azureEntities.length} Azure PII entities`);

            console.log('=== AZURE ENTITIES SAMPLE (first 20) ===');
            azureEntities.slice(0, 20).forEach((entity, index) => {
                console.log(`Azure ${index + 1}: [${entity.category}] "${entity.text}" at offset ${entity.offset}-${entity.offset + entity.length}`);
            });

            // Step 4: Run custom regex patterns
            console.log(`File ${i + 1} - Step 4: Running custom regex patterns...`);
            const customEntities = detectCustomPatterns(fullText);

            // Step 5: Merge results
            console.log(`File ${i + 1} - Step 5: Merging results...`);
            const entities = mergeEntities(azureEntities, customEntities);

            // Step 6: Apply whitelist filtering (static + dynamic)
            console.log(`File ${i + 1} - Step 6: Applying whitelist filters...`);
            console.log(`Total entities before filtering: ${entities.length}`);

            // Helper function to calculate string similarity (Levenshtein-based)
            const calculateSimilarity = (str1: string, str2: string): number => {
                const longer = str1.length > str2.length ? str1 : str2;
                const shorter = str1.length > str2.length ? str2 : str1;

                if (longer.length === 0) return 1.0;

                const editDistance = (s1: string, s2: string): number => {
                    const costs: number[] = [];
                    for (let i = 0; i <= s1.length; i++) {
                        let lastValue = i;
                        for (let j = 0; j <= s2.length; j++) {
                            if (i === 0) {
                                costs[j] = j;
                            } else if (j > 0) {
                                let newValue = costs[j - 1];
                                if (s1.charAt(i - 1) !== s2.charAt(j - 1)) {
                                    newValue = Math.min(Math.min(newValue, lastValue), costs[j]) + 1;
                                }
                                costs[j - 1] = lastValue;
                                lastValue = newValue;
                            }
                        }
                        if (i > 0) costs[s2.length] = lastValue;
                    }
                    return costs[s2.length];
                };

                return (longer.length - editDistance(longer, shorter)) / longer.length;
            };

            const filteredEntities = entities.filter(entity => {
                // FIRST: Check against static whitelist (company addresses and role words)
                if (isWhitelisted(entity.text, entity.category)) {
                    return false; // Exclude this entity (it's whitelisted)
                }

                const entityTextClean = entity.text.replace(/[\n\r]/g, ' ').trim();

                // NEW: Skip very short "Organization" entities that are likely energy scale letters
                // Azure incorrectly detects single letters A-H or small numbers as organizations
                if (entity.category === 'Organization') {
                    // Skip single letters A-H (energy ratings)
                    if (/^[A-H]\+?$/i.test(entityTextClean)) {
                        console.log(`SKIPPED [Organization] "${entityTextClean}" - likely energy rating letter`);
                        return false;
                    }
                    // Skip very short numbers (likely scale numbers like 25, 50, 75, etc.)
                    if (/^\d{1,3}$/.test(entityTextClean)) {
                        const num = parseInt(entityTextClean, 10);
                        if (num >= 0 && num <= 300) {
                            console.log(`SKIPPED [Organization] "${entityTextClean}" - likely energy scale number`);
                            return false;
                        }
                    }
                    // Skip Organizations that are just 1-2 characters (likely OCR misreads)
                    if (entityTextClean.length <= 2) {
                        console.log(`SKIPPED [Organization] "${entityTextClean}" - too short (${entityTextClean.length} chars)`);
                        return false;
                    }
                }

                const numberParts = entityTextClean.split(/\s+/).filter(s => s.length > 0);

                // Check if this looks like energy scale numbers
                if (numberParts.length >= 3) {
                    const allAreSmallNumbers = numberParts.every(part => {
                        const num = parseInt(part, 10);
                        return !isNaN(num) && num >= 0 && num <= 300;
                    });

                    // Check if numbers are evenly spaced (like 50, 75, 100, 125 - difference of 25)
                    if (allAreSmallNumbers) {
                        const nums = numberParts.map(p => parseInt(p, 10));
                        const isIncrementing = nums.every((n, i) => i === 0 || n > nums[i - 1]);

                        // Common energy scale intervals are 25 or 50
                        const firstDiff = nums.length >= 2 ? nums[1] - nums[0] : 0;
                        const isEvenlySpaced = (firstDiff === 25 || firstDiff === 50) &&
                            nums.every((n, i) => i === 0 || n - nums[i - 1] === firstDiff);

                        if (isIncrementing || isEvenlySpaced) {
                            return false;
                        }
                    }
                }

                // SECOND: If excludeAddress is provided, check against it
                if (!excludeAddress) {
                    return true; // Keep this entity (no dynamic exclusion)
                }

                // CHECK ALL ENTITY TYPES - Azure might categorize address parts differently
                // Normalize both for comparison
                const normalizedEntityText = entity.text.toLowerCase()
                    .replace(/ß/g, 'ss')
                    .replace(/ä/g, 'ae')
                    .replace(/ö/g, 'oe')
                    .replace(/ü/g, 'ue')
                    .replace(/str\./gi, 'strasse')
                    .replace(/\bstr\b/gi, 'strasse')
                    .replace(/[\r\n,\-\.]/g, ' ')
                    .replace(/\s+/g, ' ')
                    .trim();

                const normalizedExcludeAddress = excludeAddress.toLowerCase()
                    .replace(/ß/g, 'ss')
                    .replace(/ä/g, 'ae')
                    .replace(/ö/g, 'oe')
                    .replace(/ü/g, 'ue')
                    .replace(/str\./gi, 'strasse')
                    .replace(/\bstr\b/gi, 'strasse')
                    .replace(/[\r\n,\-\.]/g, ' ')
                    .replace(/\s+/g, ' ')
                    .trim();

                console.log(`\n[Checking Entity] [${entity.category}] "${entity.text}"`);

                // METHOD 1: Direct substring matching (catches partial addresses)
                if (normalizedEntityText.includes(normalizedExcludeAddress) ||
                    normalizedExcludeAddress.includes(normalizedEntityText)) {
                    console.log(`✓ SUBSTRING MATCH - EXCLUDING`);
                    return false;
                }

                // METHOD 2: Fuzzy similarity (for OCR errors)
                const similarity = calculateSimilarity(normalizedEntityText, normalizedExcludeAddress);
                if (similarity >= 0.85) {
                    console.log(`✓ HIGH SIMILARITY (${(similarity * 100).toFixed(0)}%) - EXCLUDING`);
                    return false;
                }

                // METHOD 3: Check if entity contains significant parts of excluded address
                const excludeParts = normalizedExcludeAddress.split(' ').filter(p => p.length > 2);
                const entityParts = normalizedEntityText.split(' ').filter(p => p.length > 2);

                const matchingParts = excludeParts.filter(part =>
                    entityParts.some(entityPart => {
                        if (entityPart === part) return true;
                        const partSim = calculateSimilarity(entityPart, part);
                        return partSim >= 0.85;
                    })
                );

                const matchRatio = matchingParts.length / excludeParts.length;
                if (matchRatio >= 0.6 && matchingParts.length >= 2) {
                    console.log(`✓ PARTIAL MATCH (${matchingParts.length}/${excludeParts.length} parts: ${matchingParts.join(', ')}) - EXCLUDING`);
                    return false;
                }

                // METHOD 4: Component-based matching (for address-like entities)
                const extractComponents = (addr: string) => {
                    const parts = addr.split(' ').filter(p => p.length > 0);
                    return {
                        street: parts.find(p => /strasse|str/i.test(p)) || '',
                        number: parts.find(p => /^\d+[a-z]?$/i.test(p)) || '',
                        postal: parts.find(p => /^\d{5}$/.test(p)) || '',
                        city: parts.find(p =>
                            p.length > 2 &&
                            !p.match(/strasse|str/i) &&
                            !p.match(/^\d+[a-z]?$/i) &&
                            !p.match(/^\d{5}$/)
                        ) || ''
                    };
                };

                const entityComponents = extractComponents(normalizedEntityText);
                const excludeComponents = extractComponents(normalizedExcludeAddress);

                const hasComponents = entityComponents.street || entityComponents.number ||
                    entityComponents.postal || entityComponents.city;

                if (hasComponents) {
                    let matchCount = 0;
                    const matches: string[] = [];

                    // Check street match (with fuzzy matching)
                    if (entityComponents.street && excludeComponents.street) {
                        const streetSim = calculateSimilarity(entityComponents.street, excludeComponents.street);
                        if (streetSim >= 0.75) {
                            matchCount++;
                            matches.push(`street(${(streetSim * 100).toFixed(0)}%)`);
                        }
                    }

                    // Check number match
                    if (entityComponents.number && excludeComponents.number &&
                        entityComponents.number === excludeComponents.number) {
                        matchCount++;
                        matches.push('number');
                    }

                    // Check postal code match
                    if (entityComponents.postal && excludeComponents.postal &&
                        entityComponents.postal === excludeComponents.postal) {
                        matchCount++;
                        matches.push('postal');
                    }

                    // Check city match (with fuzzy matching)
                    if (entityComponents.city && excludeComponents.city) {
                        const citySim = calculateSimilarity(entityComponents.city, excludeComponents.city);
                        if (citySim >= 0.75) {
                            matchCount++;
                            matches.push(`city(${(citySim * 100).toFixed(0)}%)`);
                        }
                    }

                    // Require 2 out of 4 components
                    if (matchCount >= 2) {
                        console.log(`✓ COMPONENT MATCH (${matchCount}/4: ${matches.join(', ')}) - EXCLUDING`);
                        return false;
                    }
                }

                console.log(`✗ No match - KEEPING`);
                return true; // Keep this entity
            });

            console.log(`Filtered entities: ${entities.length} → ${filteredEntities.length} (excluded ${entities.length - filteredEntities.length} entities)`);
            console.log(`File ${i + 1} - Total ${filteredEntities.length} PII entities after merging`);
            totalEntities += filteredEntities.length;

            // Step 7: Convert entities to redaction coordinates
            const piiRedactions = filteredEntities.length > 0
                ? convertEntitiesToRedactionCoordinates(filteredEntities, docIntelResult)
                : [];

            // Step 8: Detect signatures from handwritten styles (Azure-based)
            console.log(`File ${i + 1} - Detecting signatures...`);
            let signatureRedactions = detectSignaturesFromStyles(docIntelResult);
            console.log(`File ${i + 1} - Azure found ${signatureRedactions.length} signature redactions`);

            // Step 8b: Run YOLOS AI for additional signature detection (catches image-based signatures)
            console.log(`File ${i + 1} - Running YOLOS AI signature detection...`);
            try {
                const yoloSignatures = await detectSignaturesWithYOLO(file.buffer, signatureRedactions);
                if (yoloSignatures.length > 0) {
                    console.log(`File ${i + 1} - YOLOS found ${yoloSignatures.length} additional signatures`);
                    signatureRedactions = [...signatureRedactions, ...yoloSignatures];
                } else {
                    console.log(`File ${i + 1} - YOLOS found no additional signatures`);
                }
            } catch (yoloError) {
                console.error(`File ${i + 1} - YOLOS signature detection failed:`, yoloError);
                // Continue with Azure-only results
            }

            console.log(`File ${i + 1} - Total signature redactions: ${signatureRedactions.length}`);

            // Combine PII and signature redactions
            const redactions = [...piiRedactions, ...signatureRedactions];
            console.log(`File ${i + 1} - Total redactions: ${piiRedactions.length} PII + ${signatureRedactions.length} signatures = ${redactions.length}`);

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
            filesMerged: uploadedFiles.length,
            excludedAddress: excludeAddress || null,
            addressWasExcluded: !!excludeAddress
        };

        logInfo('PDF redaction completed successfully', {
            request_id: requestId,
            files_processed: uploadedFiles.length,
            total_redactions: totalRedactionsCount,
            total_entities: totalEntities
        });

        // Single JSON response with all redacted Base64 PDFs + merged PDF
        return NextResponse.json(responseBody);

    } catch (error: any) {
        logError('PDF redaction failed', error, {
            request_id: requestId,
            error_message: error.message,
            stack: error.stack
        });

        return NextResponse.json(
            { error: error.message || 'An unexpected error occurred' },
            { status: 500 }
        );
    }
}