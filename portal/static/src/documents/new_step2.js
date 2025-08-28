import { attachHelpText, attachTooltip } from '../forms/index.js';

const templateSelect = document.getElementById('template');
attachHelpText(templateSelect, 'Select a template to start from.');
attachTooltip(templateSelect, 'Select a template');

const uploadInput = document.getElementById('upload_file');
attachHelpText(uploadInput, 'Upload the document file.');
attachTooltip(uploadInput, 'Upload document file');

const generateDocxf = document.getElementById('generate_docxf');
attachHelpText(generateDocxf, 'Generate document from a DOCXF file.');
attachTooltip(generateDocxf, 'Generate from DOCXF');

const nextBtn = document.getElementById('next-step2');
attachTooltip(nextBtn, 'Proceed to next step');
