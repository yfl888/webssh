import { SSHTerminal } from './terminal';
import { ConnectionForm } from './auth-form';

const terminal = new SSHTerminal('terminal-container');
new ConnectionForm(terminal);

document.getElementById('disconnect-btn')?.addEventListener('click', () => {
  terminal.disconnect();
  const termSection = document.getElementById('terminal-section')!;
  termSection.classList.add('hidden');
  termSection.classList.remove('flex');
  document.getElementById('auth-section')!.classList.remove('hidden');
  document.getElementById('status-text')!.innerHTML = '<span class="w-2 h-2 bg-[#353534] inline-block"></span> STATUS: OFFLINE';
});

// Set current year for copyright
const copyrightYearSpan = document.getElementById('copyright-year');
if (copyrightYearSpan) {
  copyrightYearSpan.textContent = new Date().getFullYear().toString();
}
