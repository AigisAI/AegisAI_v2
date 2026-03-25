export function DashboardPage() {
  return <PlaceholderPage title="Dashboard" description="Dashboard widgets arrive in later issues." />;
}

function PlaceholderPage({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <section className="placeholder-card">
      <p className="eyebrow">Foundation ready</p>
      <h2>{title}</h2>
      <p>{description}</p>
    </section>
  );
}
