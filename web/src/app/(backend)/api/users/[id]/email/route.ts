import { NextRequest, NextResponse } from "next/server";

import { blockForbiddenRequests, getUserFromRequest, returnInvalidDataErrors, validBody, zodErrorHandler } from "@/utils/api";
import { AllowedRoutes } from "@/types";
import { emailSchema, userIdSchema } from "@/backend/schemas";
import { auth } from "@/auth";
import type { NextRequest as _NextRequest } from "next/server";

// typed wrapper to avoid `any` casts for better-auth calls
type ChangeEmailFn = (args: { body: { newEmail: string } }, req?: _NextRequest) => Promise<unknown>;
import { toErrorMessage } from "@/utils/api/toErrorMessage";

const allowedRoles: AllowedRoutes = {
  PATCH: ['SUPER_ADMIN', 'ADMIN', 'USER'],
}

export async function PATCH(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const forbidden = await blockForbiddenRequests(request, allowedRoles.PATCH);
    if (forbidden) {
      return forbidden;
    }

    const { id } = await params;

    const idValidationResult = userIdSchema.safeParse(id);

    if (!idValidationResult.success) {
      return NextResponse.json(
        toErrorMessage('ID Inválido'),
        { status: 400 }
      )
    }

    // garante que o request traz uma sessão e que um `USER` só possa alterar o próprio email
    const userFromRequest = await getUserFromRequest(request);

    // se for um erro (NextResponse), já retorna
    if (userFromRequest instanceof NextResponse) {
      return userFromRequest;
    }

    if (userFromRequest.role === 'USER' && id !== userFromRequest.id) {
      return NextResponse.json({ error: "Acesso negado" }, { status: 403 });
    }

    const { newEmail } = await validBody(request);
    const validationResult = emailSchema.safeParse(newEmail);

    if (!validationResult.success) {
      return returnInvalidDataErrors(validationResult.error);
    }
    
    try {
      const user = await (auth.api.changeEmail as unknown as ChangeEmailFn)(
        { body: { newEmail: validationResult.data } },
        request
      )

      return NextResponse.json(user);
    } catch (err: unknown) {
      // Dev debug: log and return error details so we can see why Better Auth fails
      // (remove in production)
       
      console.error('changeEmail error:', err);

      if (err instanceof Error) {
        return NextResponse.json({ error: { message: err.message, stack: err.stack } }, { status: 500 });
      }

      return NextResponse.json({ error: { message: 'Erro interno', details: err } }, { status: 500 });
    }
  } catch (error) {
    if (error instanceof NextResponse) {
      return error;
    }

    return zodErrorHandler(error);
  }
}