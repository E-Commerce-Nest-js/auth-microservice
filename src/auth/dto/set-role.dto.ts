import { ApiProperty } from '@nestjs/swagger';
import { IsEnum, IsMongoId, IsNotEmpty, IsString } from 'class-validator';
import { Roles } from '../../common/types/roles.type';

export class SetRoleDto {
    @ApiProperty()
    @IsNotEmpty()
    @IsString()
    @IsMongoId()
    userId: string;

    @ApiProperty({ enum: Roles })
    @IsNotEmpty()
    @IsEnum(Roles)
    @IsString()
    role: Roles;
}
