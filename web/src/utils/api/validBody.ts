import { NextResponse } from "next/server";

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function validBody(request: any) {
  try {
    const body = await request.json();
    return body;
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  } catch (e) {
    return NextResponse.json(
      { error: 'Formato de dados inválido - JSON malformado' },
      { status: 400 }
    )
  }
}