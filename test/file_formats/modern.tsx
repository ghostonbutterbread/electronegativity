type Props = {
  name?: string;
};

export function Label(props: Props) {
  const title = props.name ?? "untitled";
  return <span data-title={title}>{title}</span>;
}
