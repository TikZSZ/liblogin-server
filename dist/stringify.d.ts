declare module "json-stringify-deterministic" {
    /**
   * deterministic version of json.stringify
   */
    const _default: {
        (value: any, replacer?: ((this: any, key: string, value: any) => any) | undefined, space?: string | number | undefined): string;
        (value: any, replacer?: (string | number)[] | null | undefined, space?: string | number | undefined): string;
    };
    export default _default;
}
