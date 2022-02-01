import { prop } from '@typegoose/typegoose';
import { Base, TimeStamps } from '@typegoose/typegoose/lib/defaultClasses';
import { Roles } from 'src/common/types/roles.type';

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
