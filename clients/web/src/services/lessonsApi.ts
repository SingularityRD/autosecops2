import api from './api'
import type { Schema } from './apiTypes'

export type Lesson = Schema<'LessonResponse'>
export type LessonReplayResult = Schema<'ReplayResultResponse'>

/** Lessons from analyst corrections: replay-gated promotion and rollback (W3.11). */
export const lessonsApi = {
  list: (status?: Lesson['status']) =>
    api.get<Schema<'LessonsResponse'>>('/lessons', { params: status ? { status } : undefined }),
  replay: (id: string) =>
    api.post<LessonReplayResult>(`/lessons/${encodeURIComponent(id)}/replay`),
  promote: (id: string) =>
    api.post<LessonReplayResult>(`/lessons/${encodeURIComponent(id)}/promote`),
  rollback: (id: string, reason: string) =>
    api.post<Lesson>(`/lessons/${encodeURIComponent(id)}/rollback`, { reason }),
}
