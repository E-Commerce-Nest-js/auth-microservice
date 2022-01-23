import { Request } from 'express';

export type RequestWithUser<T> = Request & { user: T };
