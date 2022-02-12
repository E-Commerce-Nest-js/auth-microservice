import { Roles } from '../../common/types/roles.type';

export class UserResponseDto {
    _id: string;

    email: string;

    username: string;

    role: Roles;

    createdAt: string;

    updatedAt: string;
}
