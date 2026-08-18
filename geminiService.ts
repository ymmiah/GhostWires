
import { GoogleGenAI, Chat } from "@google/genai";
import type { ExtractionResult, ExtractedImage, PageContent } from './types';

// Singleton instance, lazily initialized to prevent startup crash
let ai: GoogleGenAI | null = null;
let isInitialized = false;

/**
 * Lazily initializes and returns the GoogleGenAI client instance.
 * This is designed to be safe and never throw an error on its own.
 * It returns null if initialization fails, allowing callers to handle the error gracefully.
 */
function getAiClient(): GoogleGenAI | null {
    if (isInitialized) {
        return ai;
    }

    // Per platform guidelines, process.env.API_KEY is assumed to be available.
    const apiKey = process.env.API_KEY;

    if (!apiKey) {
        console.error("CRITICAL: API_KEY environment variable not found. Ghostwire AI is offline.");
        ai = null;
    } else {
        try {
            ai = new GoogleGenAI({ apiKey });
        } catch (e) {
            console.error("CRITICAL: Failed to initialize GoogleGenAI client.", e);
            ai = null;
        }
    }
    
    isInitialized = true;
    return ai;
}

const GHOSTWIRE_MK3_PROMPT = `
You are Ghostwire Mk.III, an elite reconnaissance AI. Your mission is to conduct a deep analysis of a target website using its HTML content and URL. You operate with precision and provide structured intelligence.

**IMPORTANT CONTEXT: RENDERED HTML**
The provided HTML is the **fully rendered DOM content** of the target page, captured after client-side JavaScript has executed. This is not just raw source code. Your analysis must account for dynamically loaded content, frameworks (like React, Vue, Angular), and single-page applications. This allows you to "see" the page as a user does, providing much more accurate intelligence.

**CRITICAL INSTRUCTION: JSON FORMATTING**
Your entire output must be a single, valid JSON object that strictly conforms to the TypeScript interface provided below.
- **MANDATORY FIELDS:** The \`advancedRecon\` and \`osint\` objects are mandatory and must always be present in the final JSON output.
- **STRING ESCAPING:** This is the most common point of failure. You MUST properly escape all special characters within JSON strings.
  - **Double quotes (\`"\`)** must be escaped as \`\\"\`.
    - CORRECT: \`{ "description": "This is a \\"quoted\\" text." }\`
    - INCORRECT: \`{ "description": "This is a "quoted" text." }\`
  - **Backslashes (\`\\\`)** must be escaped as \`\\\\\\\\\`.
    - CORRECT: \`{ "path": "C:\\\\\\\\Users\\\\\\\\Default" }\`
    - INCORRECT: \`{ "path": "C:\\\\Users\\\\Default" }\` (This is invalid JSON)
  - Newlines, tabs, and other control characters must also be escaped (e.g., \`\\\\n\`, \`\\\\t\`).
  - Do NOT use invalid escape sequences like \`\\_\` or \`\\'\`. Only valid JSON escape sequences are allowed.
- **ARRAY FORMATTING:** Ensure all objects in a JSON array are separated by a comma.
    - CORRECT: \`[ { "name": "A" }, { "name": "B" } ]\`
    - INCORRECT: \`[ { "name": "A" } { "name": "B" } ]\`

The target URL is: {URL}

Here is the target's rendered HTML data stream:
---
{HTML_CONTENT}
---

Your analysis must be thorough. Extract and infer all data points specified in the following TypeScript interface. Be meticulous. If data for a specific field cannot be found, use appropriate empty values (e.g., empty strings "", empty arrays [], nulls, or "N/A" where appropriate), but the structure must remain intact.

// --- TYPE DEFINITIONS ---
interface ExtractedImage { src: string; alt: string; }
interface ExtractedLink { href: string; text: string; type: 'internal' | 'external' | 'social'; }
interface Technology { name: string; version: string; }
interface Vulnerability { cve: string; description: string; severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational'; }
interface DNSResult { a: string[]; mx: string[]; }
interface WHOISResult { registrar: string; creationDate: string; }
interface AccessibilityIssue { impact: 'critical' | 'serious' | 'moderate' | 'minor'; description: string; element: string; }
interface CMSTheme { name: string; version?: string; }
interface CMSPlugin { name: string; version?: string; }
interface ServerLocation { city: string; region: string; country: string; }
interface Person { name: string; title: string; }
interface SocialLinks { twitter?: string; linkedin?: string; github?: string; facebook?: string; }
interface SecurityHeader { name: string; value: string; }
interface SocialMeta { ogTitle?: string; ogDescription?: string; ogImage?: string; twitterCard?: string; }

interface SEOPerformanceResult {
    titleTag?: string;
    h1Tags?: string[];
    wordCount?: number;
    performanceHints?: string[];
    socialMeta?: SocialMeta;
}

interface ContentLanguageResult {
    sentiment: number; // Score from -1 (very negative) to 1 (very positive).
    readabilityScore: string; // Estimated education level required, e.g., "8th Grade", "College Level".
    detectedLanguage: string; // Primary language of the content, e.g., "English (en-US)".
    keyTopics: string[]; // Array of the most important nouns, entities, or topics.
}

interface AdvancedReconResult {
    owner: string;
    hostingPlatform: string;
    serverIP: string;
    serverLocation?: ServerLocation;
    platform: string;
    waf?: string;
    threatIntel?: string;
    cmsTheme?: CMSTheme;
    cmsPlugins?: CMSPlugin[];
    technologies: Technology[];
    vulnerabilities?: Vulnerability[];
    dnsRecords?: DNSResult;
    whois?: WHOISResult;
    securityHeaders?: SecurityHeader[];
}

interface OSINTResult {
    emails: string[];
    phoneNumbers: string[];
    addresses: string[];
    peopleLinked: Person[];
    socialLinks?: SocialLinks;
}

interface ExtractionResult {
    summary: string;
    mainContent: string;
    metaDescription: string;
    metaKeywords: string[];
    images: ExtractedImage[];
    links: ExtractedLink[];
    subdomains: string[];
    subfolders: string[];
    advancedRecon: AdvancedReconResult;
    osint: OSINTResult;
    accessibilityScore?: number;
    accessibilityIssues?: AccessibilityIssue[];
    seoPerformance?: SEOPerformanceResult;
    contentLanguage?: ContentLanguageResult; // NEW LINGUISTIC ANALYSIS
}
// --- END OF TYPE DEFINITIONS ---

**FINAL COMMAND: Your response MUST begin with \`{\` and end with \`}\`. Do not include any text, notes, or explanations before the opening brace or after the closing brace. Your entire output must be only the JSON object.**
`;

const ADVANCED_IMAGE_ANALYSIS_PROMPT = `
You are Ghostwire Mk.III's visual analysis subroutine. You will receive a list of image objects and the full HTML of the page they came from. Your mission is to provide a concise, one-sentence description for each image based on its visual content and its context within the webpage.

Target URL: {URL}
Full HTML content:
---
{HTML_CONTENT}
---

Analyze the following images. For each image, provide a detailed description. Return the result as a JSON array of objects with 'src' and 'detailedDescription'.

Images to analyze:
{IMAGES_JSON}

Respond ONLY with the JSON array.
`;

const CHAT_SYSTEM_PROMPT = `You are Ghostwire Mk.III's intelligence debriefing module. You have been provided with a comprehensive JSON report from a website reconnaissance mission. 
Your entire knowledge base for this conversation is the JSON object provided below. You must answer user questions based *only* on this data. 
Do not use any external knowledge or make assumptions beyond what is in the report.
Be concise, accurate, and maintain your AI persona. 
If the answer cannot be found in the JSON data, you must state that the information is not available in the current reconnaissance report.
Do not refer to the data as "the JSON". Refer to it as "the report", "the analysis", or "the data stream".

Here is the full reconnaissance report:
---
{EXTRACTION_RESULT_JSON}
---
`;

const PAGE_CONTENT_EXTRACTION_PROMPT = `
You are a specialized text extraction subroutine for the Ghostwire Mk.III system.
Your task is to extract the page title and provide a concise, single-paragraph summary of the main content from the provided HTML.
The summary should capture the primary purpose and key information of the page.

Your output must be a single, valid JSON object with the following structure:
{
  "title": "string",
  "summary": "string"
}

Do not include any other fields, text, or explanations. Your entire response must be only the JSON object.

HTML Content to analyze:
---
{HTML_CONTENT}
---
`;

const parseJsonResponse = (jsonString: string): any => {
    let cleanJsonString = jsonString.trim();
    const fenceRegex = /^```(\w*)?\s*\n?(.*?)\n?\s*```$/s;
    const match = cleanJsonString.match(fenceRegex);
    if (match && match[2]) {
        cleanJsonString = match[2].trim();
    }

    cleanJsonString = cleanJsonString.replace(/\\'/g, "'");

    try {
        return JSON.parse(cleanJsonString);
    } catch (e) {
        const errorMessage = e instanceof Error ? e.message : String(e);
        console.error("Fatal: Failed to parse JSON response from AI. Parser Error:", errorMessage, "Content received:", cleanJsonString);
        throw new Error(
            `AI response was not valid JSON. Parser Error: ${errorMessage}.\n\n` +
            `--- Start of AI Response ---\n` +
            `${cleanJsonString.substring(0, 500)}...\n` +
            `--- End of AI Response ---`
        );
    }
};

const AI_CLIENT_ERROR_MESSAGE = "Ghostwire AI Client is not initialized. Ensure the API_KEY is set correctly.";

export const extractWebsiteContent = async (url: string, htmlContent: string): Promise<ExtractionResult> => {
    const client = getAiClient();
    if (!client) {
        throw new Error(AI_CLIENT_ERROR_MESSAGE);
    }

    const prompt = GHOSTWIRE_MK3_PROMPT
        .replace('{URL}', url)
        .replace('{HTML_CONTENT}', htmlContent);
    
    try {
        const response = await client.models.generateContent({
            model: "gemini-2.5-flash",
            contents: prompt,
            config: {
                responseMimeType: "application/json",
            },
        });

        const jsonString = response.text;
        const parsedData = parseJsonResponse(jsonString) as ExtractionResult;

        if (!parsedData.summary || !parsedData.advancedRecon || !parsedData.osint) {
             throw new Error("Failed to get a valid analysis from the AI. The response was missing mandatory fields.");
        }
        
        return parsedData;
    } catch (e) {
        console.error("Error fetching or parsing data from Gemini API:", e);
        const message = e instanceof Error ? e.message : 'An unknown error occurred.';
        throw new Error(`Extraction protocol failed. Reason:\n${message}`);
    }
};

export const extractPageContent = async (htmlContent: string): Promise<{title: string, summary: string}> => {
    const client = getAiClient();
    if (!client) {
        throw new Error(AI_CLIENT_ERROR_MESSAGE);
    }
    
    const prompt = PAGE_CONTENT_EXTRACTION_PROMPT.replace('{HTML_CONTENT}', htmlContent);
     try {
        const response = await client.models.generateContent({
            model: "gemini-2.5-flash",
            contents: prompt,
            config: {
                responseMimeType: "application/json",
            },
        });
        const jsonString = response.text;
        const parsedData = parseJsonResponse(jsonString);

        if (!parsedData.title || !parsedData.summary) {
            throw new Error("Page content extraction failed: AI response missing title or summary.");
        }
        return parsedData;
    } catch (e) {
        console.error("Error during page content extraction:", e);
        const message = e instanceof Error ? e.message : 'An unknown error occurred during page content extraction.';
        throw new Error(message);
    }
};


export const analyzeImagesInDetail = async (
    images: ExtractedImage[],
    url: string,
    htmlContent: string
): Promise<ExtractedImage[]> => {
    const client = getAiClient();
    if (!client) {
        throw new Error(AI_CLIENT_ERROR_MESSAGE);
    }

    if (images.length === 0) return [];
    
    const imagesToAnalyze = images.map(({ src, alt }) => ({ src, alt }));
    const prompt = ADVANCED_IMAGE_ANALYSIS_PROMPT
        .replace('{URL}', url)
        .replace('{HTML_CONTENT}', htmlContent)
        .replace('{IMAGES_JSON}', JSON.stringify(imagesToAnalyze, null, 2));
    
    try {
        const response = await client.models.generateContent({
            model: "gemini-2.5-flash",
            contents: prompt,
            config: {
                responseMimeType: "application/json",
            },
        });
        
        const jsonString = response.text;
        const parsedData = parseJsonResponse(jsonString) as { src: string; detailedDescription: string }[];
        
        if (!Array.isArray(parsedData)) {
            throw new Error("AI response for image analysis was not a JSON array.");
        }
        
        const resultImages: ExtractedImage[] = images.map(originalImage => {
            const analysis = parsedData.find(p => p.src === originalImage.src);
            return {
                ...originalImage,
                detailedDescription: analysis ? analysis.detailedDescription : "Analysis failed for this image.",
            };
        });

        return resultImages;
        
    } catch (e) {
        console.error("Error during advanced image analysis:", e);
        const message = e instanceof Error ? e.message : 'An unknown error occurred.';
        throw new Error(`Image analysis protocol failed. Reason:\n${message}`);
    }
};

export const createChat = (extractionResult: ExtractionResult): Chat => {
    const client = getAiClient();
    if (!client) {
        throw new Error(AI_CLIENT_ERROR_MESSAGE);
    }

    try {
        const chat = client.chats.create({
            model: 'gemini-2.5-flash',
            config: {
                systemInstruction: CHAT_SYSTEM_PROMPT.replace('{EXTRACTION_RESULT_JSON}', JSON.stringify(extractionResult, null, 2)),
            },
        });
        return chat;
    } catch (e) {
        console.error("Failed to create chat session:", e);
        if (e instanceof Error) {
            throw new Error(`Failed to initialize chat module: ${e.message}`);
        }
        throw new Error("An unknown error occurred while initializing the chat module.");
    }
};