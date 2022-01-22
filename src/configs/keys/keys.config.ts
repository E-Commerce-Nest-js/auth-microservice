import { readFileSync } from 'fs';
import { join } from 'path';

export const getPrivateKey = (): string => {
    return readFileSync(join(__dirname + '/private.key')).toString();
};

export const getPublicKey = (): string => {
    return readFileSync(join(__dirname + '/public.key')).toString();
};
