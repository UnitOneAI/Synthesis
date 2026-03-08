import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(request: NextRequest) {
  const authToken = process.env.API_AUTH_TOKEN

  // If no auth token configured, allow all requests (local dev mode)
  if (!authToken) {
    return NextResponse.next()
  }

  const authorization = request.headers.get('authorization')
  const apiKey = request.headers.get('x-api-key')

  const providedToken = authorization?.startsWith('Bearer ')
    ? authorization.slice(7)
    : apiKey

  if (!providedToken || providedToken !== authToken) {
    return NextResponse.json(
      { error: 'Unauthorized. Set Authorization: Bearer <token> or x-api-key header.' },
      { status: 401 }
    )
  }

  return NextResponse.next()
}

export const config = {
  matcher: '/api/:path*',
}
