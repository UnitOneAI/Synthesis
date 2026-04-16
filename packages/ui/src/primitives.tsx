"use client"

import * as React from "react"

// Self-contained Badge and Button that only need Tailwind classes from the
// host app's CSS. No dependency on class-variance-authority or radix-ui.

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "outline" | "secondary" | "destructive"
}

const BADGE_VARIANTS: Record<string, string> = {
  default: "border-transparent bg-primary text-primary-foreground",
  outline: "text-foreground",
  secondary: "border-transparent bg-secondary text-secondary-foreground",
  destructive: "border-transparent bg-destructive text-destructive-foreground",
}

export function Badge({ className = "", variant = "default", ...props }: BadgeProps) {
  const base = "inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold"
  return <div className={`${base} ${BADGE_VARIANTS[variant] || ""} ${className}`} {...props} />
}

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "default" | "outline" | "secondary" | "ghost"
  size?: "default" | "sm" | "lg"
  asChild?: boolean
}

const BUTTON_VARIANTS: Record<string, string> = {
  default: "bg-primary text-primary-foreground shadow hover:bg-primary/90",
  outline: "border border-input bg-background shadow-sm hover:bg-accent hover:text-accent-foreground",
  secondary: "bg-secondary text-secondary-foreground shadow-sm hover:bg-secondary/80",
  ghost: "hover:bg-accent hover:text-accent-foreground",
}

const BUTTON_SIZES: Record<string, string> = {
  default: "h-9 px-4 py-2",
  sm: "h-8 rounded-md px-3 text-xs",
  lg: "h-10 rounded-md px-8",
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className = "", variant = "default", size = "default", asChild, children, ...props }, ref) => {
    const base =
      "inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium transition-colors disabled:pointer-events-none disabled:opacity-50"
    if (asChild && React.isValidElement(children)) {
      return React.cloneElement(children as React.ReactElement<any>, {
        className: `${base} ${BUTTON_VARIANTS[variant] || ""} ${BUTTON_SIZES[size] || ""} ${className}`,
        ref,
        ...props,
      })
    }
    return (
      <button
        className={`${base} ${BUTTON_VARIANTS[variant] || ""} ${BUTTON_SIZES[size] || ""} ${className}`}
        ref={ref}
        {...props}
      >
        {children}
      </button>
    )
  }
)
Button.displayName = "Button"
