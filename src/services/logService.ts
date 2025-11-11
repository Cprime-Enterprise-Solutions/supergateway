import { Logger } from '../types.js'
import {
  McpServerLogRepository,
  type McpServerLogDto,
} from '../lib/mcpServerLogRepository.js'
import { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js'

export interface ILogService {
  log(
    data: string | object,
    type: string,
    logger: Logger,
    session: { ip: string; userId: string; sessionId: string },
  ): Promise<void>
}

export class LogService implements ILogService {
  constructor(private readonly repository: McpServerLogRepository) {}

  async log(
    data: string | object,
    type: string,
    logger: Logger,
    session: { ip: string; userId: string; sessionId: string },
  ): Promise<void> {
    const logDto: McpServerLogDto = {
      ip: session.ip,
      userId: session.userId,
      sessionId: session.sessionId,
      type: type as McpServerLogDto['type'],
      data: data as JSONRPCMessage | string,
      createdAt: new Date(),
      updatedAt: new Date(),
    }

    // Insert to MongoDB with error handling
    try {
      await this.repository.insert(logDto)
    } catch (err) {
      logger.error(`Failed to insert log:`, JSON.stringify(err))
    }
  }
}
