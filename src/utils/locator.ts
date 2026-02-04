import * as fs from 'fs';
import jsonToAst from 'json-to-ast'; // Changed to default import

export interface Location {
    startLine: number;
    endLine: number;
}

export async function findJsonLocation(filePath: string, packageName: string): Promise<Location | undefined> {
    try {
        const content = await fs.promises.readFile(filePath, 'utf-8');
        const ast = jsonToAst(content);

        if (ast.type !== 'Object' || !ast.children) return undefined;

        // Traverse AST to find dependencies
        // We look for "dependencies", "devDependencies", "peerDependencies"
        const depTypes = ['dependencies', 'devDependencies', 'peerDependencies'];

        for (const prop of ast.children) {
            if (prop.key && depTypes.includes(prop.key.value)) {
                if (prop.value && prop.value.type === 'Object' && prop.value.children) {
                    for (const dep of prop.value.children) {
                        if (dep.key.value === packageName) {
                            return {
                                startLine: dep.loc?.start.line || 0,
                                endLine: dep.loc?.end.line || 0
                            };
                        }
                    }
                }
            }
        }
    } catch (e) {
        console.error("JSON parse error:", e);
    }
    return undefined;
}

export async function findGoModLocation(filePath: string, packageName: string): Promise<Location | undefined> {
    try {
        const content = await fs.promises.readFile(filePath, 'utf-8');
        const lines = content.split('\n');

        // Basic parsing for go.mod
        // require (
        //     github.com/foo/bar v1.0.0
        // )
        // OR require github.com/foo/bar v1.0.0

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (line.startsWith('require')) {
                // Check inline
                if (line.includes(packageName)) {
                    return { startLine: i + 1, endLine: i + 1 };
                }
            } else {
                // Check inside block (very naive, assumes we are inside require block if indented)
                // Better: check if line contains package name and looks like a dependency
                if (line.includes(packageName) && !line.startsWith('//') && !line.startsWith('module')) {
                    return { startLine: i + 1, endLine: i + 1 };
                }
            }
        }

    } catch (e) { }
    return undefined;
}

/**
 * Find package location in Python requirements.txt
 * Format: package==version or package>=version etc.
 */
export async function findRequirementsTxtLocation(filePath: string, packageName: string): Promise<Location | undefined> {
    try {
        const content = await fs.promises.readFile(filePath, 'utf-8');
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            // Skip comments and empty lines
            if (line.startsWith('#') || line === '') continue;

            // Match package name (handles ==, >=, <=, ~=, !=, etc.)
            const pkgMatch = line.match(/^([a-zA-Z0-9_-]+)/);
            if (pkgMatch && pkgMatch[1].toLowerCase() === packageName.toLowerCase()) {
                return { startLine: i + 1, endLine: i + 1 };
            }
        }
    } catch (e) { }
    return undefined;
}

/**
 * Find gem location in Ruby Gemfile
 * Format: gem 'package', 'version' or gem "package"
 */
export async function findGemfileLocation(filePath: string, packageName: string): Promise<Location | undefined> {
    try {
        const content = await fs.promises.readFile(filePath, 'utf-8');
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            // Skip comments
            if (line.startsWith('#')) continue;

            // Match: gem 'name' or gem "name"
            const gemMatch = line.match(/gem\s+['"]([^'"]+)['"]/);
            if (gemMatch && gemMatch[1].toLowerCase() === packageName.toLowerCase()) {
                return { startLine: i + 1, endLine: i + 1 };
            }
        }
    } catch (e) { }
    return undefined;
}

/**
 * Find crate location in Rust Cargo.toml
 * Format: package = "version" in [dependencies] section
 */
export async function findCargoTomlLocation(filePath: string, packageName: string): Promise<Location | undefined> {
    try {
        const content = await fs.promises.readFile(filePath, 'utf-8');
        const lines = content.split('\n');
        let inDependencies = false;

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();

            // Check for section headers
            if (line.startsWith('[')) {
                inDependencies = line.includes('dependencies');
                continue;
            }

            if (inDependencies) {
                // Match: package_name = "version" or package_name = { ... }
                const match = line.match(/^([a-zA-Z0-9_-]+)\s*=/);
                if (match && match[1].toLowerCase() === packageName.toLowerCase()) {
                    return { startLine: i + 1, endLine: i + 1 };
                }
            }
        }
    } catch (e) { }
    return undefined;
}

/**
 * Find dependency location in Java pom.xml
 * Format: <artifactId>package</artifactId> inside <dependency>
 */
export async function findPomXmlLocation(filePath: string, packageName: string): Promise<Location | undefined> {
    try {
        const content = await fs.promises.readFile(filePath, 'utf-8');
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            // Match <artifactId>name</artifactId>
            const artifactMatch = line.match(/<artifactId>([^<]+)<\/artifactId>/);
            if (artifactMatch && artifactMatch[1].toLowerCase() === packageName.toLowerCase()) {
                return { startLine: i + 1, endLine: i + 1 };
            }
        }
    } catch (e) { }
    return undefined;
}

// =============== LOCK FILE PARSERS ===============

/**
 * Find package location in package-lock.json (npm)
 * Structure: "packages" or "dependencies" with nested package objects
 */
export async function findPackageLockLocation(filePath: string, packageName: string): Promise<Location | undefined> {
    try {
        const content = await fs.promises.readFile(filePath, 'utf-8');
        const lines = content.split('\n');

        // Search for the package name as a key in the JSON
        // Format: "package-name": { or "node_modules/package-name": {
        const packagePattern = new RegExp(`"(node_modules/)?${escapeRegex(packageName)}"\\s*:`);

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (packagePattern.test(line)) {
                return { startLine: i + 1, endLine: i + 1 };
            }
        }
    } catch (e) { }
    return undefined;
}

/**
 * Find package location in yarn.lock
 * Format:
 * "package-name@version":
 *   version "x.x.x"
 *   resolved "..."
 */
export async function findYarnLockLocation(filePath: string, packageName: string): Promise<Location | undefined> {
    try {
        const content = await fs.promises.readFile(filePath, 'utf-8');
        const lines = content.split('\n');

        // Match: "package-name@version": or package-name@version:
        const packagePattern = new RegExp(`^"?${escapeRegex(packageName)}@`);

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (packagePattern.test(line)) {
                return { startLine: i + 1, endLine: i + 1 };
            }
        }
    } catch (e) { }
    return undefined;
}

/**
 * Find crate location in Cargo.lock (Rust)
 * Format:
 * [[package]]
 * name = "crate-name"
 * version = "x.x.x"
 */
export async function findCargoLockLocation(filePath: string, packageName: string): Promise<Location | undefined> {
    try {
        const content = await fs.promises.readFile(filePath, 'utf-8');
        const lines = content.split('\n');

        // Look for: name = "package-name"
        const namePattern = new RegExp(`^name\\s*=\\s*"${escapeRegex(packageName)}"$`);

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (namePattern.test(line)) {
                return { startLine: i + 1, endLine: i + 1 };
            }
        }
    } catch (e) { }
    return undefined;
}

/**
 * Find module location in go.sum
 * Format: github.com/user/package v1.0.0 h1:hash=
 */
export async function findGoSumLocation(filePath: string, packageName: string): Promise<Location | undefined> {
    try {
        const content = await fs.promises.readFile(filePath, 'utf-8');
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            // go.sum format: module version hash
            // The module path might be a full path or partial
            if (line.startsWith(packageName) || line.includes('/' + packageName + ' ')) {
                return { startLine: i + 1, endLine: i + 1 };
            }
        }
    } catch (e) { }
    return undefined;
}

/**
 * Helper function to escape special regex characters in package names
 */
function escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
