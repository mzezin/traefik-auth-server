declare module 'htpasswd-js' {
  export function authenticate({username: string, password: string, data: string} ): Promise<boolean>;
} 