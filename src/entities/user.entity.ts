import { ApiProperty } from '@nestjs/swagger';
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';

@Entity('users')
export class User {
  @ApiProperty()
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty()
  @Index({ unique: true })
  @Column({ length: 150 })
  email: string;

  @Column()
  password: string;

  @ApiProperty()
  @Column({ nullable: true })
  name?: string;

  @ApiProperty()
  @Column({ nullable: true })
  avatarUrl?: string;

  @Column({ type: 'text', nullable: true })
  refreshTokenHash?: string | null;

  @ApiProperty()
  @Column({ default: true })
  isActive: boolean;

  @ApiProperty()
  @CreateDateColumn()
  createdAt: Date;

  @ApiProperty()
  @UpdateDateColumn()
  updatedAt: Date;

  @ApiProperty()
  @Column({ type: 'text', default: 'user' })
  role: 'user' | 'admin';

  @ApiProperty()
  @Column({ type: 'datetime', nullable: true })
  lastLogin?: Date;
}
