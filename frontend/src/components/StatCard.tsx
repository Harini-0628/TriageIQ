interface StatCardProps {
  label: string;
  value: string | number;
  tone?: "default" | "danger" | "warning" | "success";
}

const toneClasses: Record<string, string> = {
  default: "text-slate-900",
  danger: "text-red-600",
  warning: "text-amber-600",
  success: "text-emerald-600",
};

export function StatCard({ label, value, tone = "default" }: StatCardProps) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-5">
      <p className="text-sm font-medium text-slate-500">{label}</p>
      <p className={`mt-2 text-2xl font-bold ${toneClasses[tone]}`}>{value}</p>
    </div>
  );
}
