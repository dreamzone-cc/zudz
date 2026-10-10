<script lang="ts">
  import { tr } from '$lib/i18n';

  /// شريط تقدم العملية — يعرض المستوى الحالي والمراحل
  /// percent: 0-100 — stages: مفاتيح الترجمة للمراحل — active: فهرس المرحلة الجارية
  export let percent = 0;
  export let stages: string[] = [];
  export let active = 0;
  export let done = false;

  function clamp(): number {
    return Math.max(0, Math.min(100, Math.round(percent)));
  }
</script>

<div class="prog" role="progressbar" aria-valuenow={clamp()} aria-valuemin="0" aria-valuemax="100">
  <div class="prog-head">
    <span class="prog-label">{done ? $tr('progress.done') : (stages[active] ? $tr(stages[active]) : '')}</span>
    <span class="prog-pct">{clamp()}%</span>
  </div>
  <div class="prog-track">
    <div class="prog-fill" class:done style="width:{clamp()}%"></div>
  </div>
  {#if stages.length > 1}
    <div class="prog-steps">
      {#each stages as s, i}
        <span class="step" class:on={i < active || done} class:cur={i === active && !done}>
          <span class="dot">{i < active || done ? '✓' : (i + 1)}</span>
          {$tr(s)}
        </span>
      {/each}
    </div>
  {/if}
</div>

<style>
  .prog { margin-block: 12px; }
  .prog-head { display: flex; justify-content: space-between; font-size: 0.82rem; color: var(--dim); margin-block-end: 6px; }
  .prog-pct { font-family: var(--mono); color: var(--acc); }
  .prog-track { height: 8px; border-radius: 99px; background: #0a0f1a; border: 1px solid var(--line); overflow: hidden; }
  .prog-fill { height: 100%; border-radius: 99px; background: linear-gradient(90deg, var(--acc), var(--ok));
    transition: width .35s ease; }
  .prog-fill.done { background: var(--ok); }
  .prog-steps { display: flex; flex-wrap: wrap; gap: 6px 14px; margin-block-start: 8px; font-size: 0.74rem; color: var(--dim); }
  .step { display: inline-flex; align-items: center; gap: 5px; }
  .step .dot { display: inline-flex; align-items: center; justify-content: center;
    width: 15px; height: 15px; border-radius: 50%; background: var(--card2);
    border: 1px solid var(--line); font-size: 0.62rem; }
  .step.on { color: var(--ok); }
  .step.on .dot { background: rgba(58, 210, 154, 0.15); border-color: var(--ok); }
  .step.cur { color: var(--acc); }
  .step.cur .dot { border-color: var(--acc); }
</style>
