import { exec } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { promisify } from 'node:util';
import JSZip from 'jszip';
import { fileAnalysisJobSchema, } from '../../shared/analysis-types.js';
import { appConfig } from '../config.js';
import { getStoragePaths } from '../storage.js';
const execAsync = promisify(exec);
const fileAnalysisJobs = new Map();
const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024;
const EXECUTABLE_EXTENSIONS = new Set(['exe', 'dll', 'scr', 'js', 'jse', 'vbs', 'vbe', 'hta', 'bat', 'cmd', 'ps1']);
const MACRO_EXTENSIONS = new Set(['docm', 'xlsm', 'pptm']);
export class FileAnalysisError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.code = code;
    }
}
export async function enqueueFileAnalysisJob(files, analyzeUploadedFile = analyzeUploadedFileStatically, enrichFileWithThreatIntel = lookupFileThreatIntel, createJobId = randomUUID) {
    const normalizedFiles = normalizeFiles(files);
    const jobId = createJobId();
    const queuedJob = fileAnalysisJobSchema.parse({
        jobId,
        status: 'queued',
        queuedFiles: normalizedFiles.map((file) => file.filename),
        results: [],
    });
    fileAnalysisJobs.set(jobId, queuedJob);
    queueMicrotask(async () => {
        try {
            await runFileAnalysisJob(jobId, normalizedFiles, analyzeUploadedFile, enrichFileWithThreatIntel);
        }
        catch (error) {
            fileAnalysisJobs.set(jobId, buildFailedFileAnalysisJob(jobId, normalizedFiles, error));
        }
    });
    return queuedJob;
}
export async function getFileAnalysisJob(jobId) {
    return fileAnalysisJobs.get(jobId) ?? null;
}
export async function createFileAnalysisJob(files, analyzeUploadedFile = analyzeUploadedFileStatically, enrichFileWithThreatIntel = lookupFileThreatIntel, createJobId = randomUUID) {
    const normalizedFiles = normalizeFiles(files);
    const jobId = createJobId();
    const results = await Promise.all(normalizedFiles.map(async (file, index) => {
        const analysis = await analyzeUploadedFile(file, { jobId, index });
        const virustotal = await enrichFileWithThreatIntel(analysis.sha256);
        return {
            ...analysis,
            externalScans: {
                ...analysis.externalScans,
                virustotal,
            },
        };
    }));
    return fileAnalysisJobSchema.parse({
        jobId,
        status: results.every((result) => result.verdict !== 'malicious' || result.summary.length > 0) ? 'completed' : 'failed',
        queuedFiles: normalizedFiles.map((file) => file.filename),
        results,
    });
}
export async function analyzeUploadedFileStatically(file, context) {
    const buffer = decodeBase64(file.contentBase64);
    if (buffer.byteLength > MAX_FILE_SIZE_BYTES) {
        throw new FileAnalysisError('file_too_large', 'Files larger than 10 MB are not supported in the MVP analyzer.');
    }
    const uploadDirectory = path.join(getStoragePaths().uploads, context.jobId);
    await fs.mkdir(uploadDirectory, { recursive: true });
    const safeFilename = sanitizeFilename(file.filename, context.index);
    const storagePath = path.join(uploadDirectory, safeFilename);
    await fs.writeFile(storagePath, buffer);
    const sha256 = createHash('sha256').update(buffer).digest('hex');
    const extension = extractExtension(file.filename);
    const detectedType = detectFileType(buffer, extension);
    const extractedUrls = extractUrls(buffer);
    const indicators = [];
    const parserReports = await buildParserReports({
        buffer,
        detectedType,
        extension,
        filename: file.filename,
        extractedUrls,
    });
    if (hasDoubleExtension(file.filename)) {
        indicators.push({ kind: 'double_extension', severity: 'high', value: file.filename });
    }
    if (extension && EXECUTABLE_EXTENSIONS.has(extension)) {
        indicators.push({ kind: 'executable_extension', severity: 'high', value: extension });
    }
    if (buffer.subarray(0, 2).toString('ascii') === 'MZ') {
        indicators.push({ kind: 'pe_header', severity: 'high', value: 'MZ header detected' });
    }
    if (detectedType === 'pdf' && /\/JavaScript|\/JS|\/OpenAction/i.test(buffer.toString('latin1'))) {
        indicators.push({ kind: 'pdf_javascript', severity: 'high', value: 'Embedded PDF JavaScript markers found' });
    }
    if ((extension && MACRO_EXTENSIONS.has(extension)) || /vbaProject\.bin/i.test(buffer.toString('latin1'))) {
        indicators.push({ kind: 'office_macro', severity: 'high', value: 'Macro-enabled Office indicators found' });
    }
    if (detectedType === 'zip' || detectedType === 'archive') {
        indicators.push({ kind: 'archive', severity: 'medium', value: 'Archive container detected' });
    }
    if (extractedUrls.length > 0) {
        indicators.push({ kind: 'embedded_url', severity: 'medium', value: `${extractedUrls.length} embedded URL(s)` });
    }
    indicators.push(...parserReports.flatMap(buildIndicatorsFromParserReport));
    const localScans = await runLocalFileScanners({
        filename: file.filename,
        filePath: storagePath,
        sha256,
    });
    indicators.push(...buildIndicatorsFromExternalScans(localScans));
    const deduplicatedIndicators = deduplicateIndicators(indicators);
    const artifacts = buildFileArtifacts({
        filename: file.filename,
        storagePath,
        contentType: file.contentType ?? null,
        size: buffer.byteLength,
    });
    const riskScore = Math.min(100, deduplicatedIndicators.reduce((score, indicator) => score + severityWeight(indicator.severity), 0));
    const verdict = riskScore >= 70 ? 'malicious' : riskScore >= 25 ? 'suspicious' : 'clean';
    const summary = buildStaticAnalysisSummary({
        verdict,
        indicators: deduplicatedIndicators,
        parserReports,
        scans: localScans,
    });
    return {
        filename: file.filename,
        contentType: file.contentType ?? null,
        detectedType,
        extension,
        size: buffer.byteLength,
        sha256,
        extractedUrls,
        indicators: deduplicatedIndicators,
        parserReports,
        riskScore,
        verdict,
        summary,
        storagePath,
        artifacts,
        externalScans: {
            virustotal: emptyVirusTotalScan(),
            clamav: localScans.clamav,
            yara: localScans.yara,
        },
    };
}
async function runFileAnalysisJob(jobId, files, analyzeUploadedFile, enrichFileWithThreatIntel) {
    fileAnalysisJobs.set(jobId, {
        jobId,
        status: 'running',
        queuedFiles: files.map((file) => file.filename),
        results: [],
    });
    const results = [];
    for (const [index, file] of files.entries()) {
        try {
            const analysis = await analyzeUploadedFile(file, { jobId, index });
            const virustotal = await enrichFileWithThreatIntel(analysis.sha256);
            results.push({
                ...analysis,
                externalScans: {
                    ...analysis.externalScans,
                    virustotal,
                },
            });
        }
        catch (error) {
            const decoded = safeDecode(file.contentBase64);
            results.push({
                filename: file.filename,
                contentType: file.contentType ?? null,
                detectedType: 'unknown',
                extension: extractExtension(file.filename),
                size: decoded?.byteLength ?? 0,
                sha256: decoded ? createHash('sha256').update(decoded).digest('hex') : '',
                extractedUrls: [],
                indicators: [],
                parserReports: [],
                riskScore: 0,
                verdict: 'clean',
                summary: error instanceof Error ? error.message : 'File analysis failed unexpectedly.',
                storagePath: null,
                artifacts: [],
                externalScans: {
                    virustotal: emptyVirusTotalScan(),
                    clamav: emptyClamAvScan('unavailable'),
                    yara: emptyYaraScan('unavailable'),
                },
            });
        }
    }
    fileAnalysisJobs.set(jobId, fileAnalysisJobSchema.parse({
        jobId,
        status: 'completed',
        queuedFiles: files.map((file) => file.filename),
        results,
    }));
}
function buildFailedFileAnalysisJob(jobId, files, error) {
    const message = error instanceof Error ? error.message : 'File analysis failed unexpectedly.';
    return fileAnalysisJobSchema.parse({
        jobId,
        status: 'failed',
        queuedFiles: files.map((file) => file.filename),
        results: files.map((file) => {
            const decoded = safeDecode(file.contentBase64);
            return {
                filename: file.filename,
                contentType: file.contentType ?? null,
                detectedType: 'unknown',
                extension: extractExtension(file.filename),
                size: decoded?.byteLength ?? 0,
                sha256: decoded ? createHash('sha256').update(decoded).digest('hex') : '',
                extractedUrls: [],
                indicators: [],
                parserReports: [],
                riskScore: 0,
                verdict: 'clean',
                summary: message,
                storagePath: null,
                artifacts: [],
                externalScans: {
                    virustotal: emptyVirusTotalScan(),
                    clamav: emptyClamAvScan('unavailable'),
                    yara: emptyYaraScan('unavailable'),
                },
            };
        }),
    });
}
export async function lookupFileThreatIntel(hash) {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) {
        return { status: 'not_configured', malicious: null, suspicious: null, reference: null };
    }
    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/files/${encodeURIComponent(hash)}`, {
            headers: { 'x-apikey': apiKey },
            signal: AbortSignal.timeout(10000),
        });
        if (response.status === 404) {
            return { status: 'clean', malicious: 0, suspicious: 0, reference: null };
        }
        if (!response.ok) {
            return { status: 'unavailable', malicious: null, suspicious: null, reference: null };
        }
        const payload = (await response.json());
        const malicious = payload.data?.attributes?.last_analysis_stats?.malicious ?? 0;
        const suspicious = payload.data?.attributes?.last_analysis_stats?.suspicious ?? 0;
        return {
            status: malicious > 0 || suspicious > 0 ? 'malicious' : 'clean',
            malicious,
            suspicious,
            reference: payload.data?.links?.self ?? null,
        };
    }
    catch {
        return { status: 'unavailable', malicious: null, suspicious: null, reference: null };
    }
}
async function buildParserReports(context) {
    const reports = [];
    if (context.detectedType === 'pdf') {
        reports.push(buildPdfParserReport(context.buffer, context.extractedUrls));
    }
    if (context.detectedType === 'office-openxml' || context.detectedType === 'zip' || context.detectedType === 'archive') {
        reports.push(await buildArchiveParserReport(context.buffer, context.detectedType));
    }
    if (context.detectedType === 'pe') {
        reports.push(buildPeParserReport(context.buffer));
    }
    if (context.detectedType === 'script') {
        reports.push(buildScriptParserReport(context.buffer, context.extension));
    }
    if (reports.length === 0) {
        reports.push({
            parser: 'generic',
            summary: `Basic binary heuristics applied to ${context.filename}.`,
            details: [
                `Detected type: ${context.detectedType}`,
                `Extracted URLs: ${context.extractedUrls.length}`,
            ],
            snippets: [],
        });
    }
    return reports;
}
function buildPdfParserReport(buffer, extractedUrls) {
    const content = buffer.toString('latin1');
    const objectCount = (content.match(/\b\d+\s+\d+\s+obj\b/g) ?? []).length;
    const autoActions = ['/OpenAction', '/Launch', '/AA'].filter((token) => content.includes(token));
    const snippets = extractSnippetMatches(content, [/\/JavaScript/gi, /\/JS/gi, /\/OpenAction/gi, /\/Launch/gi], 180);
    return {
        parser: 'pdf',
        summary: `PDF parser found ${objectCount} object(s) and ${autoActions.length} auto-action marker(s).`,
        details: [
            `Embedded URLs: ${extractedUrls.length}`,
            `JavaScript markers: ${/\/JavaScript|\/JS/i.test(content) ? 'present' : 'absent'}`,
            `Auto actions: ${autoActions.length ? autoActions.join(', ') : 'none'}`,
        ],
        snippets,
    };
}
async function buildArchiveParserReport(buffer, detectedType) {
    try {
        const zip = await JSZip.loadAsync(buffer);
        const entryNames = Object.keys(zip.files).slice(0, 12);
        const details = [`Entries: ${entryNames.length}`];
        const snippets = [];
        if (entryNames.length) {
            details.push(`Sample entries: ${entryNames.join(', ')}`);
        }
        const macroEntry = entryNames.find((entryName) => /vbaProject\.bin/i.test(entryName));
        if (macroEntry) {
            details.push(`Macro payload: ${macroEntry}`);
            const macroBuffer = await zip.file(macroEntry)?.async('nodebuffer');
            if (macroBuffer) {
                snippets.push(...extractPrintableMacroSnippets(macroBuffer));
            }
        }
        const relCandidates = Object.values(zip.files).filter((entry) => entry.name.endsWith('.rels')).slice(0, 4);
        for (const candidate of relCandidates) {
            const content = await candidate.async('text');
            if (/TargetMode="External"|https?:\/\//i.test(content)) {
                details.push(`External relationship found in ${candidate.name}`);
                snippets.push(...extractSnippetMatches(content, [/TargetMode="External"/gi, /https?:\/\/[^\s"']+/gi], 160));
            }
        }
        return {
            parser: detectedType === 'office-openxml' ? 'office-openxml' : 'archive',
            summary: `${detectedType === 'office-openxml' ? 'Office OpenXML' : 'Archive'} parser inspected ${Object.keys(zip.files).length} container entr${Object.keys(zip.files).length === 1 ? 'y' : 'ies'}.`,
            details,
            snippets: snippets.slice(0, 5),
        };
    }
    catch (error) {
        return {
            parser: detectedType === 'office-openxml' ? 'office-openxml' : 'archive',
            summary: 'Archive parser could not fully inspect the container.',
            details: [error instanceof Error ? error.message : 'Unknown archive parsing error'],
            snippets: [],
        };
    }
}
function buildPeParserReport(buffer) {
    const peOffset = buffer.length >= 64 ? buffer.readUInt32LE(0x3c) : 0;
    const details = [`PE header offset: ${peOffset}`];
    if (peOffset > 0 && buffer.length >= peOffset + 24 && buffer.subarray(peOffset, peOffset + 4).toString('ascii') === 'PE\u0000\u0000') {
        const sectionCount = buffer.readUInt16LE(peOffset + 6);
        details.push(`Section count: ${sectionCount}`);
        const firstSectionOffset = peOffset + 24 + buffer.readUInt16LE(peOffset + 20);
        const sectionNames = [];
        for (let index = 0; index < Math.min(sectionCount, 6); index += 1) {
            const sectionOffset = firstSectionOffset + index * 40;
            if (sectionOffset + 8 > buffer.length) {
                break;
            }
            const name = buffer.subarray(sectionOffset, sectionOffset + 8).toString('ascii').replace(/\u0000+$/g, '');
            if (name) {
                sectionNames.push(name);
            }
        }
        if (sectionNames.length) {
            details.push(`Sections: ${sectionNames.join(', ')}`);
        }
    }
    else {
        details.push('PE signature not fully readable.');
    }
    return {
        parser: 'pe',
        summary: 'PE parser inspected DOS and NT headers.',
        details,
        snippets: [],
    };
}
function buildScriptParserReport(buffer, extension) {
    const scriptContent = buffer.toString('utf8');
    const normalizedContent = scriptContent.toLowerCase();
    const markers = [
        'eval(',
        'frombase64string',
        'invoke-expression',
        'wscript.shell',
        'activexobject',
        'powershell -enc',
    ].filter((marker) => normalizedContent.includes(marker));
    return {
        parser: 'script',
        summary: `Script parser inspected ${extension ?? 'unknown'} content and found ${markers.length} suspicious marker(s).`,
        details: markers.length ? markers.map((marker) => `Marker: ${marker}`) : ['No high-risk script markers found.'],
        snippets: extractSuspiciousScriptSnippets(scriptContent, markers),
    };
}
function buildIndicatorsFromParserReport(report) {
    if (report.parser === 'script') {
        return report.details
            .filter((detail) => detail.startsWith('Marker: '))
            .map((detail) => ({
            kind: 'suspicious_script',
            severity: 'high',
            value: detail.replace('Marker: ', ''),
        }));
    }
    if (report.parser === 'office-openxml' || report.parser === 'archive') {
        return report.details
            .filter((detail) => detail.startsWith('Macro payload: '))
            .map((detail) => ({
            kind: 'office_macro',
            severity: 'high',
            value: detail.replace('Macro payload: ', ''),
        }));
    }
    return [];
}
function buildIndicatorsFromExternalScans(scans) {
    const indicators = [];
    if (scans.clamav.status === 'malicious' && scans.clamav.signature) {
        indicators.push({ kind: 'clamav_match', severity: 'high', value: scans.clamav.signature });
    }
    if (scans.yara.status === 'match') {
        for (const rule of scans.yara.rules) {
            indicators.push({ kind: 'yara_match', severity: 'high', value: rule });
        }
    }
    return indicators;
}
function buildStaticAnalysisSummary(context) {
    if (context.verdict === 'clean') {
        return 'No high-confidence malicious indicators were found during static analysis.';
    }
    const headline = context.indicators[0]?.value ?? 'embedded content';
    const scanNotes = [];
    if (context.scans.clamav.status === 'malicious' && context.scans.clamav.signature) {
        scanNotes.push(`ClamAV matched ${context.scans.clamav.signature}.`);
    }
    if (context.scans.yara.status === 'match' && context.scans.yara.rules.length > 0) {
        scanNotes.push(`YARA matched ${context.scans.yara.rules.join(', ')}.`);
    }
    return [
        `Static analysis found ${context.indicators.length} suspicious indicator(s), including ${headline}.`,
        scanNotes[0] ?? `${context.parserReports.length} specialized parser report(s) were generated.`,
    ].join(' ');
}
function buildFileArtifacts(context) {
    return [
        {
            type: 'upload',
            label: context.filename,
            path: context.storagePath,
            mimeType: context.contentType,
            size: context.size,
        },
    ];
}
async function runLocalFileScanners(context, runCommand = execScannerCommand) {
    const [clamav, yara] = await Promise.all([
        runClamAvScan(context, runCommand),
        runYaraScan(context, runCommand),
    ]);
    return { clamav, yara };
}
async function runClamAvScan(context, runCommand) {
    const template = appConfig.fileAnalysis.clamavCommandTemplate;
    if (!template) {
        return emptyClamAvScan('not_configured');
    }
    const command = interpolateScannerCommand(template, context);
    try {
        const { stdout, stderr } = await runCommand(command);
        return parseClamAvOutput(`${stdout}\n${stderr}`);
    }
    catch (error) {
        const stdout = readCommandStream(error, 'stdout');
        const stderr = readCommandStream(error, 'stderr');
        const parsed = parseClamAvOutput(`${stdout}\n${stderr}`);
        if (parsed.status === 'malicious' || parsed.status === 'clean') {
            return parsed;
        }
        return {
            ...emptyClamAvScan('error'),
            detail: stderr.trim() || (error instanceof Error ? error.message : 'ClamAV scan failed unexpectedly.'),
        };
    }
}
async function runYaraScan(context, runCommand) {
    const template = appConfig.fileAnalysis.yaraCommandTemplate;
    if (!template) {
        return emptyYaraScan('not_configured');
    }
    const command = interpolateScannerCommand(template, context);
    try {
        const { stdout, stderr } = await runCommand(command);
        return parseYaraOutput(stdout, stderr);
    }
    catch (error) {
        const stdout = readCommandStream(error, 'stdout');
        const stderr = readCommandStream(error, 'stderr');
        const parsed = parseYaraOutput(stdout, stderr);
        if (parsed.status === 'match' || parsed.status === 'clean') {
            return parsed;
        }
        return {
            ...emptyYaraScan('error'),
            detail: stderr.trim() || (error instanceof Error ? error.message : 'YARA scan failed unexpectedly.'),
        };
    }
}
async function execScannerCommand(command) {
    return execAsync(command);
}
function parseClamAvOutput(output) {
    const meaningfulLine = output
        .split(/\r?\n/)
        .map((line) => line.trim())
        .find((line) => line.includes(':'));
    if (!meaningfulLine) {
        return emptyClamAvScan('clean');
    }
    const verdict = meaningfulLine.split(':').slice(1).join(':').trim();
    if (/\bOK\b/i.test(verdict)) {
        return emptyClamAvScan('clean');
    }
    if (verdict) {
        return {
            status: 'malicious',
            signature: verdict.replace(/\s+FOUND$/i, '').trim(),
            engine: 'ClamAV',
            detail: meaningfulLine,
        };
    }
    return emptyClamAvScan('unavailable');
}
function parseYaraOutput(stdout, stderr) {
    const rules = stdout
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => line.split(/\s+/)[0])
        .filter(Boolean);
    if (rules.length > 0) {
        return {
            status: 'match',
            rules: [...new Set(rules)],
            detail: null,
        };
    }
    if (stderr.trim()) {
        return {
            ...emptyYaraScan('error'),
            detail: stderr.trim(),
        };
    }
    return emptyYaraScan('clean');
}
function interpolateScannerCommand(template, context) {
    return template
        .replaceAll(':path', shellEscape(context.filePath))
        .replaceAll(':filename', shellEscape(context.filename))
        .replaceAll(':sha256', context.sha256);
}
function readCommandStream(error, key) {
    if (typeof error === 'object' && error !== null && key in error) {
        const value = error[key];
        return typeof value === 'string' ? value : '';
    }
    return '';
}
function emptyVirusTotalScan() {
    return {
        status: 'unavailable',
        malicious: null,
        suspicious: null,
        reference: null,
    };
}
function emptyClamAvScan(status) {
    return {
        status,
        signature: null,
        engine: status === 'not_configured' ? null : 'ClamAV',
        detail: null,
    };
}
function emptyYaraScan(status) {
    return {
        status,
        rules: [],
        detail: null,
    };
}
function deduplicateIndicators(indicators) {
    const seen = new Set();
    return indicators.filter((indicator) => {
        const key = `${indicator.kind}:${indicator.value}`;
        if (seen.has(key)) {
            return false;
        }
        seen.add(key);
        return true;
    });
}
function normalizeFiles(files) {
    if (files.length === 0) {
        throw new FileAnalysisError('invalid_file_upload', 'At least one file is required for analysis.');
    }
    return files.map((file) => {
        if (!file.filename.trim()) {
            throw new FileAnalysisError('invalid_file_upload', 'Every uploaded file must include a filename.');
        }
        const decoded = decodeBase64(file.contentBase64);
        if (decoded.byteLength === 0) {
            throw new FileAnalysisError('invalid_file_upload', 'Uploaded files must not be empty.');
        }
        if (decoded.byteLength > MAX_FILE_SIZE_BYTES) {
            throw new FileAnalysisError('file_too_large', 'Files larger than 10 MB are not supported in the MVP analyzer.');
        }
        return {
            ...file,
            contentType: file.contentType ?? null,
        };
    });
}
function decodeBase64(contentBase64) {
    try {
        return Buffer.from(contentBase64, 'base64');
    }
    catch {
        throw new FileAnalysisError('invalid_file_upload', 'One or more uploaded files are not valid base64 payloads.');
    }
}
function safeDecode(contentBase64) {
    try {
        return Buffer.from(contentBase64, 'base64');
    }
    catch {
        return null;
    }
}
function sanitizeFilename(filename, index) {
    const cleaned = filename.replace(/[\\/:*?"<>|]+/g, '-').trim();
    return `${index.toString().padStart(2, '0')}-${cleaned || 'upload.bin'}`;
}
function extractExtension(filename) {
    const lastSegment = filename.split('.').pop()?.toLowerCase() ?? '';
    return lastSegment.length > 0 && lastSegment !== filename.toLowerCase() ? lastSegment : null;
}
function hasDoubleExtension(filename) {
    const parts = filename.toLowerCase().split('.').filter(Boolean);
    return parts.length >= 3;
}
function detectFileType(buffer, extension) {
    const header = buffer.subarray(0, 8).toString('latin1');
    if (header.startsWith('%PDF')) {
        return 'pdf';
    }
    if (buffer.subarray(0, 2).toString('ascii') === 'MZ') {
        return 'pe';
    }
    if (buffer.subarray(0, 4).toString('latin1') === 'PK\u0003\u0004') {
        if (extension && ['docx', 'xlsx', 'pptx', 'docm', 'xlsm', 'pptm'].includes(extension)) {
            return 'office-openxml';
        }
        return 'zip';
    }
    if (extension && ['7z', 'rar', 'zip'].includes(extension)) {
        return 'archive';
    }
    if (extension && ['js', 'vbs', 'ps1', 'bat', 'cmd'].includes(extension)) {
        return 'script';
    }
    return extension ?? 'unknown';
}
function extractUrls(buffer) {
    const content = buffer.toString('utf8');
    return [...new Set(content.match(/https?:\/\/[^\s<>"']+/gi) ?? [])];
}
function extractSnippetMatches(content, patterns, radius) {
    const snippets = [];
    for (const pattern of patterns) {
        for (const match of content.matchAll(pattern)) {
            if (typeof match.index !== 'number') {
                continue;
            }
            const start = Math.max(0, match.index - radius);
            const end = Math.min(content.length, match.index + match[0].length + radius);
            const snippet = content.slice(start, end).replace(/\s+/g, ' ').trim();
            if (snippet) {
                snippets.push(snippet);
            }
            if (snippets.length >= 5) {
                return [...new Set(snippets)];
            }
        }
    }
    return [...new Set(snippets)];
}
function extractSuspiciousScriptSnippets(content, markers) {
    const lines = content.split(/\r?\n/);
    const snippets = [];
    for (const marker of markers) {
        const matchingLine = lines.find((line) => line.toLowerCase().includes(marker));
        if (matchingLine) {
            snippets.push(matchingLine.trim());
        }
    }
    return [...new Set(snippets)].slice(0, 5);
}
function extractPrintableMacroSnippets(buffer) {
    const suspiciousMarkers = ['AutoOpen', 'Document_Open', 'Shell', 'CreateObject', 'WScript', 'PowerShell', 'http', 'cmd.exe'];
    return buffer
        .toString('latin1')
        .replace(/[^\x20-\x7e\r\n\t]+/g, ' ')
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line.length >= 8)
        .filter((line) => suspiciousMarkers.some((marker) => line.toLowerCase().includes(marker.toLowerCase())))
        .slice(0, 5);
}
function shellEscape(value) {
    return `"${value.replace(/"/g, '\\"')}"`;
}
function severityWeight(severity) {
    switch (severity) {
        case 'high':
            return 40;
        case 'medium':
            return 20;
        case 'low':
        default:
            return 10;
    }
}
