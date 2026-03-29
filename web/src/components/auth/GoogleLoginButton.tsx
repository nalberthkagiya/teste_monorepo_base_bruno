'use client'
import clsx from "clsx";
import Image from "next/image";
// import { useSearchParams } from "next/navigation";
import { isSafeRedirect } from "@/utils";

import { authClient } from "@/lib/auth-client";
import { ButtonHTMLAttributes } from "react";

interface GoogleAuthButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  className?: string;
  text?: string;
};

function GoogleAuthButton({ className, text, ...props }: GoogleAuthButtonProps) {
  // const searchParams = useSearchParams();
  // const callbackUrl = searchParams.get('callbackUrl') ?? "/";
  const callbackUrl = "/";
  const safeCallbackUrl = isSafeRedirect(callbackUrl) ? callbackUrl : "/";
  
  return ( 
      <div
        className={clsx("w-full flex-1", className)}
      >
        <input type="hidden" name="type" value="google" />

        <button type="submit" className='login-button tracking-4' {...props}
        onClick={async () => {
          if (props.disabled) {
            return
          } 
          await authClient.signIn.social({
            provider: "google",
            callbackURL: safeCallbackUrl,
          });
        }}>
            <Image
              src={`/icons/google-logo.png`}
              alt={`Google logo`}
              width={24}
              height={24}
            />

          {text}
        </button>
      </div>
    );
}

export default GoogleAuthButton;