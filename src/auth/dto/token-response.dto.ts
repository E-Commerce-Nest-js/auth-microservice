import { ApiProperty } from '@nestjs/swagger';

export class TokenResponseDto {
    @ApiProperty()
    access_token: string;
}
