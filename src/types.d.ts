declare module 'json-to-ast' {
    interface ASTNode {
        type: string;
        loc?: {
            start: { line: number; column: number };
            end: { line: number; column: number };
        };
        children?: ASTNode[]; // For Object/Array
        key?: ASTNode;       // For Property
        value?: any;
    }

    function parse(json: string, settings?: any): ASTNode;
    export = parse;
}
