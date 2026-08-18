export const createAbsoluteUrl = (href: string, base: string): string => {
    try {
        if (!href || href.startsWith('mailto:') || href.startsWith('tel:')) {
            return '';
        }
        // Correctly pass through data URIs without trying to parse them as URLs
        if (href.startsWith('data:')) {
            return href;
        }
        if (href.startsWith('http://') || href.startsWith('https://') || href.startsWith('//')) {
            if (href.startsWith('//')) {
                 // Use the base URL's protocol for protocol-relative URLs
                const baseProtocol = new URL(base).protocol;
                return new URL(`${baseProtocol}${href}`).href;
            }
            return new URL(href).href;
        }
        return new URL(href, base).href;
    } catch (e) {
        console.error(`Failed to create absolute URL for href: "${href}" with base: "${base}"`, e);
        return '';
    }
};
