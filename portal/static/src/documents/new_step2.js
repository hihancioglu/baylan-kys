import { attachHelpText, attachTooltip } from '../forms/index.js';

const templateSelect = document.getElementById('template');
attachHelpText(templateSelect, 'Select a template to start from.');
attachTooltip(templateSelect, 'Select a template');

const uploadInput = document.getElementById('upload_file');
attachHelpText(uploadInput, 'Upload the document file.');
attachTooltip(uploadInput, 'Upload document file');

const nextBtn = document.getElementById('next-step2');
attachTooltip(nextBtn, 'Proceed to next step');
