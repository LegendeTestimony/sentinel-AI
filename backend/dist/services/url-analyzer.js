import fetch from 'node-fetch';
import { analyzeFile } from './file-analyzer.js';
async function followRedirects(url, maxRedirects = 10) {
    const redirectChain = [url];
    let currentUrl = url;
    let redirectCount = 0;
    while (redirectCount < maxRedirects) {
        try {
            const response = await fetch(currentUrl, {
                method: 'GET',
                redirect: 'manual',
                headers: {
                    'User-Agent': 'Sentinel-AI-Security-Scanner/1.0',
                },
            });
            // Check for redirect status codes
            if (response.status >= 300 && response.status < 400) {
                const location = response.headers.get('location');
                if (!location)
                    break;
                // Handle relative URLs
                const nextUrl = new URL(location, currentUrl).href;
                redirectChain.push(nextUrl);
                currentUrl = nextUrl;
                redirectCount++;
            }
            else {
                // No more redirects
                break;
            }
        }
        catch (error) {
            console.error('Redirect following error:', error);
            break;
        }
    }
    return {
        finalUrl: currentUrl,
        redirectChain,
    };
}
function extractWebpageInfo(html, baseUrl) {
    const baseDomain = new URL(baseUrl).hostname;
    // Extract title
    const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    const title = titleMatch ? titleMatch[1].trim() : undefined;
    // Extract scripts
    const scriptRegex = /<script[^>]*src=["']([^"']+)["']/gi;
    const scripts = [];
    let scriptMatch;
    while ((scriptMatch = scriptRegex.exec(html)) !== null) {
        scripts.push(scriptMatch[1]);
    }
    // Extract inline scripts (look for suspicious patterns)
    const inlineScriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
    let inlineMatch;
    while ((inlineMatch = inlineScriptRegex.exec(html)) !== null) {
        const scriptContent = inlineMatch[1];
        // Check for suspicious patterns
        if (scriptContent.includes('eval(') ||
            scriptContent.includes('document.write(') ||
            scriptContent.includes('unescape(') ||
            scriptContent.includes('atob(') ||
            scriptContent.includes('fromCharCode(')) {
            scripts.push('[INLINE:SUSPICIOUS]');
        }
    }
    // Extract iframes
    const iframeRegex = /<iframe[^>]*src=["']([^"']+)["']/gi;
    const iframes = [];
    let iframeMatch;
    while ((iframeMatch = iframeRegex.exec(html)) !== null) {
        iframes.push(iframeMatch[1]);
    }
    // Extract forms
    const formRegex = /<form[^>]*action=["']([^"']+)["']/gi;
    const forms = [];
    let formMatch;
    while ((formMatch = formRegex.exec(html)) !== null) {
        forms.push(formMatch[1]);
    }
    // Extract external links
    const linkRegex = /<a[^>]*href=["']([^"']+)["']/gi;
    const externalLinks = [];
    let linkMatch;
    while ((linkMatch = linkRegex.exec(html)) !== null) {
        try {
            const linkUrl = new URL(linkMatch[1], baseUrl);
            if (linkUrl.hostname !== baseDomain) {
                externalLinks.push(linkUrl.href);
            }
        }
        catch {
            // Ignore invalid URLs
        }
    }
    return {
        title,
        scripts: [...new Set(scripts)],
        iframes: [...new Set(iframes)],
        forms: [...new Set(forms)],
        externalLinks: [...new Set(externalLinks)].slice(0, 20), // Limit to first 20
    };
}
export async function analyzeURL(url) {
    console.log(`🌐 Starting URL analysis: ${url}`);
    // Validate URL
    let parsedUrl;
    try {
        parsedUrl = new URL(url);
    }
    catch (error) {
        throw new Error('Invalid URL format');
    }
    // Follow redirects
    console.log('🔄 Following redirects...');
    const { finalUrl, redirectChain } = await followRedirects(url);
    console.log(`📍 Final URL: ${finalUrl} (${redirectChain.length} redirect(s))`);
    // Fetch content
    console.log('📥 Fetching content...');
    const response = await fetch(finalUrl, {
        method: 'GET',
        headers: {
            'User-Agent': 'Sentinel-AI-Security-Scanner/1.0',
        },
        timeout: 10000, // 10 second timeout
    });
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    const contentType = response.headers.get('content-type') || '';
    console.log(`📄 Content-Type: ${contentType}`);
    // Get content as buffer
    const buffer = await response.buffer();
    let webpage;
    // If HTML, extract webpage info
    if (contentType.includes('text/html')) {
        const html = buffer.toString('utf-8');
        webpage = extractWebpageInfo(html, finalUrl);
        console.log(`🔍 Webpage analysis: ${webpage.scripts.length} scripts, ${webpage.iframes.length} iframes, ${webpage.forms.length} forms`);
    }
    // Create a mock file object from the fetched content
    const mockFile = {
        buffer,
        originalname: finalUrl.split('/').pop() || 'downloaded-file',
        mimetype: contentType.split(';')[0].trim(),
        size: buffer.length,
    };
    // Analyze the downloaded content
    console.log('🔬 Analyzing downloaded content...');
    const fileAnalysis = await analyzeFile(mockFile);
    // Build URL-specific result
    const urlAnalysis = {
        ...fileAnalysis,
        url: {
            original: url,
            final: finalUrl,
            redirectChain,
            protocol: parsedUrl.protocol,
            domain: parsedUrl.hostname,
        },
        webpage,
    };
    console.log(`✅ URL analysis complete: ${urlAnalysis.threat.level}`);
    return urlAnalysis;
}
