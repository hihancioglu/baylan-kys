import { attachHelpText, attachTooltip } from '../forms/index.js';

const code = document.getElementById('code');
attachHelpText(code, 'Unique identifier for the document.');
attachTooltip(code, 'Unique document code');

const titleInput = document.getElementById('title');
attachHelpText(titleInput, 'Title of the document.');
attachTooltip(titleInput, 'Document title');

const typeInput = document.getElementById('type');
attachHelpText(typeInput, 'Type of document.');
attachTooltip(typeInput, 'Document type');

const departmentInput = document.getElementById('department');
attachHelpText(departmentInput, 'Department responsible for the document.');
attachTooltip(departmentInput, 'Responsible department');

const standardSelect = document.getElementById('standard');
attachHelpText(standardSelect, 'Choose the standard that applies.');
attachTooltip(standardSelect, 'Applicable standard');

const tagsInput = document.getElementById('tags');
attachHelpText(tagsInput, 'Add comma-separated tags.');
attachTooltip(tagsInput, 'Comma-separated tags');

const nextBtn = document.getElementById('next-step1');
attachTooltip(nextBtn, 'Proceed to next step');
