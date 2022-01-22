import { prop } from '@typegoose/typegoose';
import { Base, TimeStamps } from '@typegoose/typegoose/lib/defaultClasses';

export enum Roles {
    Admin = 'admin',
    Manager = 'manager',
    User = 'user',
}

export interface UserModel extends Base {}

export class UserModel extends TimeStamps {
    @prop({ unique: true })
    email: string;

    @prop()
    passwordHash: string;

    @prop()
    username: string;

    @prop()
    refresh_token?: string;

    @prop({ enum: Roles })
    role: Roles;
}
