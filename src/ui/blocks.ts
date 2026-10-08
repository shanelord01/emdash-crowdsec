/**
 * The Block Kit constructors this plugin needs.
 *
 * Not `blocks`/`elements` from `@emdash-cms/blocks/server`: importing them
 * would carry the package into the runtime bundle, which the plugin build
 * inlines whole. The types are imported as types only and erased.
 *
 * What matters is the keys. The renderer reads snake_case (`action_id`,
 * `block_id`, `empty_text`) and silently ignores camelCase, so every block
 * is built here against upstream's own interfaces, where a wrong key is a
 * compile error, and the tests run upstream's `validateBlocks()` over what
 * the pages produce.
 */

import type { BannerBlock, ChartBlock, CodeBlock } from "@emdash-cms/blocks";
import type {
	ActionElement,
	ActionsBlock,
	ButtonElement,
	ColumnsBlock,
	ConfirmDialog,
	ContextBlock,
	FieldsBlock,
	FormBlock,
	FormField,
	HeaderBlock,
	LinkElement,
	LinkTarget,
	MenuElement,
	SectionBlock,
	SelectElement,
	StatItem,
	StatsBlock,
	TableBlock,
	TableColumn,
	TextInputElement,
} from "@emdash-cms/blocks/server";

export function stats(items: StatItem[], opts?: { blockId?: string }): StatsBlock {
	return { type: "stats", items, ...(opts?.blockId !== undefined && { block_id: opts.blockId }) };
}

export function context(text: string, opts?: { blockId?: string }): ContextBlock {
	return { type: "context", text, ...(opts?.blockId !== undefined && { block_id: opts.blockId }) };
}

export function actions(elements: ActionElement[], opts?: { blockId?: string }): ActionsBlock {
	return { type: "actions", elements, ...(opts?.blockId !== undefined && { block_id: opts.blockId }) };
}

export function button(
	actionId: string,
	label: string,
	opts?: { style?: "primary" | "danger" | "secondary"; value?: unknown; confirm?: ConfirmDialog },
): ButtonElement {
	return {
		type: "button",
		action_id: actionId,
		label,
		...(opts?.style !== undefined && { style: opts.style }),
		...(opts?.value !== undefined && { value: opts.value }),
		...(opts?.confirm !== undefined && { confirm: opts.confirm }),
	};
}

export function confirmDialog(title: string, text: string, confirm: string, deny: string): ConfirmDialog {
	return { title, text, confirm, deny, style: "danger" };
}

export function link(label: string, target: LinkTarget, opts?: { appearance?: "inline" | "primary" | "secondary" }): LinkElement {
	return { type: "link", label, target, ...(opts?.appearance !== undefined && { appearance: opts.appearance }) };
}

export function menu(actionId: string, label: string, items: Array<{ label: string; value: string }>): MenuElement {
	return { type: "menu", action_id: actionId, label, items, style: "secondary" };
}

export function select(
	actionId: string,
	label: string,
	options: Array<{ label: string; value: string }>,
	opts?: { initialValue?: string },
): SelectElement {
	return {
		type: "select",
		action_id: actionId,
		label,
		options,
		...(opts?.initialValue !== undefined && { initial_value: opts.initialValue }),
	};
}

export function textInput(actionId: string, label: string, opts?: { placeholder?: string; initialValue?: string }): TextInputElement {
	return {
		type: "text_input",
		action_id: actionId,
		label,
		...(opts?.placeholder !== undefined && { placeholder: opts.placeholder }),
		...(opts?.initialValue !== undefined && { initial_value: opts.initialValue }),
	};
}

export function form(fields: FormField[], submit: { label: string; actionId: string }, opts?: { blockId?: string }): FormBlock {
	return {
		type: "form",
		fields,
		submit: { label: submit.label, action_id: submit.actionId },
		...(opts?.blockId !== undefined && { block_id: opts.blockId }),
	};
}

export function section(text: string, opts?: { accessory?: ActionElement; blockId?: string }): SectionBlock {
	return {
		type: "section",
		text,
		...(opts?.accessory !== undefined && { accessory: opts.accessory }),
		...(opts?.blockId !== undefined && { block_id: opts.blockId }),
	};
}

export function fields(items: Array<{ label: string; value: string }>, opts?: { blockId?: string }): FieldsBlock {
	return { type: "fields", fields: items, ...(opts?.blockId !== undefined && { block_id: opts.blockId }) };
}

export function banner(opts: { title?: string; description?: string; variant?: "default" | "alert" | "error"; blockId?: string }): BannerBlock {
	return {
		type: "banner",
		...(opts.title !== undefined && { title: opts.title }),
		...(opts.description !== undefined && { description: opts.description }),
		...(opts.variant !== undefined && { variant: opts.variant }),
		...(opts.blockId !== undefined && { block_id: opts.blockId }),
	};
}

export function code(text: string, opts?: { language?: CodeBlock["language"] }): CodeBlock {
	return { type: "code", code: text, ...(opts?.language !== undefined && { language: opts.language }) };
}

export function header(text: string, opts?: { blockId?: string }): HeaderBlock {
	return { type: "header", text, ...(opts?.blockId !== undefined && { block_id: opts.blockId }) };
}

export function columns(cols: SecurityBlock[][], opts?: { blockId?: string }): ColumnsBlock {
	return {
		type: "columns",
		columns: cols as ColumnsBlock["columns"],
		...(opts?.blockId !== undefined && { block_id: opts.blockId }),
	};
}

/** One series of a daily chart: a value per day label, null where the day has no figure. */
export interface DailySeries {
	name: string;
	data: Array<number | null>;
	colour?: string;
}

/**
 * The host's categorical chart palette in light mode, in kumo's order
 * (Blue, Yellow, Pink, Purple, Teal, Orange). A colour set in the options
 * replaces the host's palette in both modes, so a series keeps its colour
 * on every chart.
 */
export const CHART_COLOURS = ["#4290F0", "#F5B647", "#E8649D", "#8D58EE", "#50C3B6", "#D37536"] as const;

/**
 * A chart of one value per day, drawn as `chart_type: "custom"` with a
 * category x-axis of day labels ("27 Sept").
 *
 * Not `timeseries`: its tooltip formats the x value as a timestamp in the
 * viewer's zone, so a day showed with an hour attached and could land on
 * the wrong date, and it cannot leave a gap for a day without a figure.
 * A custom chart's tooltip uses the category label. The host strips every
 * `formatter` key from custom options, so the options are plain data.
 */
export function dailyChart(opts: {
	labels: string[];
	series: DailySeries[];
	style: "line" | "bar";
	height: number;
	blockId?: string;
}): ChartBlock {
	const drawn = opts.series.filter((s) => s.data.some((v) => typeof v === "number" && v > 0));
	return {
		type: "chart",
		config: {
			chart_type: "custom",
			height: opts.height,
			options: {
				aria: { enabled: true },
				tooltip: { trigger: "axis" },
				xAxis: { type: "category", data: opts.labels, boundaryGap: opts.style === "bar", axisLine: { show: false }, splitLine: { show: false } },
				yAxis: {
					type: "value",
					minInterval: 1,
					axisTick: { show: true },
					axisLabel: { margin: 15 },
					splitLine: { show: true, lineStyle: { type: "dashed", width: 1 } },
				},
				grid: { left: 24, right: 24, top: 24, bottom: 24 },
				series: drawn.map((s) => ({
					type: opts.style,
					name: s.name,
					data: s.data,
					emphasis: { focus: "series" },
					...(s.colour !== undefined && { itemStyle: { color: s.colour } }),
					...(opts.style === "bar" ? { stack: "total" } : { showSymbol: true, symbolSize: 4, connectNulls: false }),
				})),
			},
		},
		...(opts.blockId !== undefined && { block_id: opts.blockId }),
	};
}

export function table(opts: {
	blockId?: string;
	columns: TableColumn[];
	rows: Array<Record<string, unknown>>;
	pageActionId: string;
	nextCursor?: string;
	emptyText?: string;
}): TableBlock {
	return {
		type: "table",
		columns: opts.columns,
		rows: opts.rows,
		page_action_id: opts.pageActionId,
		...(opts.nextCursor !== undefined && { next_cursor: opts.nextCursor }),
		...(opts.emptyText !== undefined && { empty_text: opts.emptyText }),
		...(opts.blockId !== undefined && { block_id: opts.blockId }),
	};
}

/** `empty` is accepted by the renderer and the validator, though missing from the server export's type list. */
export interface EmptyBlockShape {
	type: "empty";
	title?: string;
	description?: string;
	actions?: ActionElement[];
	block_id?: string;
}

export function empty(opts: { title?: string; description?: string; actions?: ActionElement[]; blockId?: string }): EmptyBlockShape {
	return {
		type: "empty",
		...(opts.title !== undefined && { title: opts.title }),
		...(opts.description !== undefined && { description: opts.description }),
		...(opts.actions !== undefined && { actions: opts.actions }),
		...(opts.blockId !== undefined && { block_id: opts.blockId }),
	};
}

/** Every block shape this plugin can emit. */
export type SecurityBlock =
	| StatsBlock
	| ContextBlock
	| ActionsBlock
	| TableBlock
	| EmptyBlockShape
	| HeaderBlock
	| ColumnsBlock
	| ChartBlock
	| BannerBlock
	| CodeBlock
	| FormBlock
	| SectionBlock
	| FieldsBlock;
