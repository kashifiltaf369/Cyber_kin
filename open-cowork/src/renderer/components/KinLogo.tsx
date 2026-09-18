export function KinLogo({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 40 40"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      <rect width="40" height="40" rx="10" fill="#11151A" />
      <path
        d="M12 28V12h3.5l6.5 11V12H26v16h-3.5l-6.5-11v11H12z"
        fill="#38BDF8"
      />
    </svg>
  );
}
