import { IsEnum, IsMongoId, IsNotEmpty, IsString } from 'class-validator';
import { Roles } from '../../common/types/roles.type';

export class SetRoleDto {
    @IsNotEmpty()
    @IsString()
    @IsMongoId()
    userId: string;

    @IsNotEmpty()
    @IsEnum(Roles)
    @IsString()
    role: string;
}
