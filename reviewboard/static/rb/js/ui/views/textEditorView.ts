import { BaseView, EventsHash, spina } from '@beanbag/spina';
import CodeMirror from 'codemirror';

import { UserSession } from 'reviewboard/common/models/userSessionModel';

import { DnDUploader } from './dndUploaderView';


/*
 * Define a CodeMirror mode we can plug in as the default below.
 *
 * This mode won't have any special highlighting, but will avoid the Markdown
 * mode's default behavior of rendering "plain/text" code (the default) the
 * same way as literal code, which we really want to avoid.
 */
CodeMirror.defineSimpleMode('rb-text-plain', {
    start: [
        {
            next: 'start',
            regex: /.*/,
            token: 'rb-cm-codeblock-plain',
        },
    ],
});

CodeMirror.defineMIME('text/plain', 'rb-text-plain');


/**
 * Options for the editor wrapper views.
 *
 * Version Added:
 *     6.0
 */
interface EditorWrapperOptions {
    /**
     * Whether the editor should automatically resize to fit its container.
     */
    autoSize?: boolean;

    /**
     * The minimum vertical size of the editor.
     */
    minHeight?: number;

    /**
     * The parent element for the editor.
     */
    parentEl?: Element;
}


/**
 * Wraps CodeMirror, providing a standard interface for TextEditorView's usage.
 */
@spina
class CodeMirrorWrapper extends BaseView<
    Backbone.Model,
    HTMLDivElement,
    EditorWrapperOptions
> {
    /**********************
     * Instance variables *
     **********************/

    _codeMirror: CodeMirror;

    /**
     * Initialize CodeMirrorWrapper.
     *
     * This will set up CodeMirror based on the objects, add it to the parent,
     * and begin listening to events.
     *
     * Args:
     *     options (EditorWrapperOptions):
     *         Options for the wrapper.
     */
    initialize(options: EditorWrapperOptions) {
        const codeMirrorOptions = {
            electricChars: false,
            extraKeys: {
                'End': 'goLineRight',
                'Enter': 'newlineAndIndentContinueMarkdownList',
                'Home': 'goLineLeft',
                'Shift-Tab': false,
                'Tab': false,
            },
            lineWrapping: true,
            mode: {
                highlightFormatting: true,
                name: 'gfm',

                /*
                 * The following token type overrides will be prefixed with
                 * ``cm-`` when used as classes.
                 */
                tokenTypeOverrides: {
                    code: 'rb-markdown-code',
                    list1: 'rb-markdown-list1',
                    list2: 'rb-markdown-list2',
                    list3: 'rb-markdown-list3',
                },
            },
            styleSelectedText: true,
            theme: 'rb default',
            viewportMargin: options.autoSize ? Infinity : 10,
        };

        this._codeMirror = new CodeMirror(options.parentEl,
                                          codeMirrorOptions);

        this.setElement(this._codeMirror.getWrapperElement());

        if (options.minHeight !== undefined) {
            this.$el.css('min-height', options.minHeight);
        }

        this._codeMirror.on('viewportChange',
                            () => this.$el.triggerHandler('resize'));
        this._codeMirror.on('change', () => this.trigger('change'));
    }

    /**
     * Return whether or not the editor's contents have changed.
     *
     * Args:
     *     initialValue (string):
     *         The initial value of the editor.
     *
     * Returns:
     *     boolean:
     *     Whether or not the editor is dirty.
     */
    isDirty(
        initialValue: string,
    ): boolean {
        /*
         * We cannot trust codeMirror's isClean() method.
         *
         * It is also possible for initialValue to be undefined, so we use an
         * empty string in that case instead.
         */
        return (initialValue || '') !== this.getText();
    }

    /**
     * Set the text in the editor.
     *
     * Args:
     *     text (string):
     *         The new text for the editor.
     */
    setText(text: string) {
        this._codeMirror.setValue(text);
    }

    /**
     * Return the text in the editor.
     *
     * Returns:
     *     string:
     *     The current contents of the editor.
     */
    getText(): string {
        return this._codeMirror.getValue();
    }

    /**
     * Insert a new line of text into the editor.
     *
     * If the editor has focus, insert at the cursor position. Otherwise,
     * insert at the end.
     *
     * Args:
     *     text (string):
     *         The text to insert.
     */
    insertLine(text: string) {
        let position;

        if (this._codeMirror.hasFocus()) {
            const cursor = this._codeMirror.getCursor();
            const line = this._codeMirror.getLine(cursor.line);
            position = CodeMirror.Pos(cursor.line, line.length - 1);

            if (line.length !== 0) {
                /*
                 * If the current line has some content, insert the new text on
                 * the line after it.
                 */
                text = '\n' + text;
            }

            if (!text.endsWith('\n')) {
                text += '\n';
            }
        } else {
            position = CodeMirror.Pos(this._codeMirror.lastLine());
            text = '\n' + text;
        }

        this._codeMirror.replaceRange(text, position);
    }

    /**
     * Return the full client height of the content.
     *
     * Returns:
     *     number:
     *     The client height of the editor.
     */
    getClientHeight(): number {
        return this._codeMirror.getScrollInfo().clientHeight;
    }

    /**
     * Set the size of the editor.
     *
     * Args:
     *     width (number):
     *         The new width of the editor.
     *
     *     height (number):
     *         The new height of the editor.
     */
    setSize(
        width: number,
        height: number,
    ) {
        this._codeMirror.setSize(width, height);
        this._codeMirror.refresh();
    }

    /**
     * Focus the editor.
     */
    focus() {
        this._codeMirror.focus();
    }
}


/**
 * Wraps <textarea>, providing a standard interface for TextEditorView's usage.
 */
@spina
class TextAreaWrapper extends BaseView<
    Backbone.Model,
    HTMLTextAreaElement,
    EditorWrapperOptions
> {
    static tagName = 'textarea';

    /**********************
     * Instance variables *
     **********************/

    options: EditorWrapperOptions;

    /*
     * Initialize TextAreaWrapper.
     *
     * This will set up the element based on the provided options, begin
     * listening for events, and add the element to the parent.
     *
     * Args:
     *     options (EditorWrapperOptions):
     *         Options for the wrapper.
     */
    initialize(options: EditorWrapperOptions) {
        this.options = options;

        if (options.autoSize) {
            this.$el.autoSizeTextArea();
        }

        this.$el
            .css('width', '100%')
            .appendTo(options.parentEl)
            .on('change keydown keyup keypress', () => this.trigger('change'));

        if (options.minHeight !== undefined) {
            if (options.autoSize) {
                this.$el.autoSizeTextArea('setMinHeight',
                                          options.minHeight);
            } else {
                this.$el.css('min-height', this.options.minHeight);
            }
        }
    }

    /**
     * Return whether or not the editor's contents have changed.
     *
     * Args:
     *     initialValue (string):
     *         The initial value of the editor.
     *
     * Returns:
     *     boolean:
     *     Whether or not the editor is dirty.
     */
    isDirty(
        initialValue: string,
    ): boolean {
        const value = this.el.value || '';

        return value.length !== initialValue.length ||
               value !== initialValue;
    }

    /**
     * Set the text in the editor.
     *
     * Args:
     *     text (string):
     *         The new text for the editor.
     */
    setText(text: string) {
        this.el.value = text;

        if (this.options.autoSize) {
            this.$el.autoSizeTextArea('autoSize');
        }
    }

    /**
     * Return the text in the editor.
     *
     * Returns:
     *     string:
     *     The current contents of the editor.
     */
    getText(): string {
        return this.el.value;
    }

    /**
     * Insert a new line of text into the editor.
     *
     * Args:
     *     text (string):
     *         The text to insert.
     */
    insertLine(text: string) {
        if (this.$el.is(':focus')) {
            const value = this.el.value;
            const cursor = this.el.selectionEnd;
            const endOfLine = value.indexOf('\n', cursor);

            if (endOfLine === -1) {
                // The cursor is on the last line.
                this.el.value += '\n' + text;
            } else {
                // The cursor is in the middle of the text.
                this.el.value = (value.slice(0, endOfLine + 1) + '\n' + text +
                                 '\n' + value.slice(endOfLine));
            }
        } else {
            this.el.value += '\n' + text;
        }
    }

    /**
     * Return the full client height of the content.
     *
     * Returns:
     *     number:
     *     The client height of the editor.
     */
    getClientHeight(): number {
        return this.el.clientHeight;
    }

    /**
     * Set the size of the editor.
     *
     * Args:
     *     width (number):
     *         The new width of the editor.
     *
     *     height (number):
     *         The new height of the editor.
     */
    setSize(
        width: number | string,
        height: number | string,
    ) {
        if (width !== null) {
            this.$el.innerWidth(width);
        }

        if (height !== null) {
            if (height === 'auto' && this.options.autoSize) {
                this.$el.autoSizeTextArea('autoSize', true);
            } else {
                this.$el.innerHeight(height);
            }
        }
    }

    /**
     * Focus the editor.
     */
    focus() {
        this.el.focus();
    }
}


/**
 * Options for the FormattingToolbarView.
 *
 * Version Added:
 *     6.0
 */
interface FormattingToolbarViewOptions {
    /** The CodeMirror wrapper object. */
    editor: CodeMirrorWrapper;
}


interface FormattingToolbarButton {
    /**
     * The class to apply to the element.
     */
    className: string;

    /**
     * The name of a callback function when the button is clicked.
     */
    onClick?: string;

    /**
     * HTML contet to use instead of creating a new button.
     */
    $content?: JQuery;
}


/**
 * The formatting toolbar for rich text fields.
 *
 * Version Added:
 *     6.0
 */
@spina
class FormattingToolbarView extends BaseView<
    Backbone.Model,
    HTMLDivElement,
    FormattingToolbarViewOptions
> {
    static className = 'rb-c-formatting-toolbar';

    static template = dedent`
        <div class="rb-c-formatting-toolbar__btn-group">
         <a href="#" class="rb-c-formatting-toolbar__btn rb-c-formatting-toolbar__btn-bold"></a>
         <a href="#" class="rb-c-formatting-toolbar__btn rb-c-formatting-toolbar__btn-italic"></a>
         <a href="#" class="rb-c-formatting-toolbar__btn rb-c-formatting-toolbar__btn-strikethrough"></a>
        </div>
        <div class="rb-c-formatting-toolbar__btn-group">
         <a href="#" class="rb-c-formatting-toolbar__btn rb-c-formatting-toolbar__btn-link"></a>
         <label class="rb-c-formatting-toolbar__btn rb-c-formatting-toolbar__btn-image"
                aria-role="button" tabindex="0">
          <input type="file" style="display: none;">
         </label>
         <a href="#" class="rb-c-formatting-toolbar__btn rb-c-formatting-toolbar__btn-code"></a>
        </div>
        <div class="rb-c-formatting-toolbar__btn-group">
         <a href="#" class="rb-c-formatting-toolbar__btn rb-c-formatting-toolbar__btn-list-ul"></a>
         <a href="#" class="rb-c-formatting-toolbar__btn rb-c-formatting-toolbar__btn-list-ol"></a>
        </div>
    `;

    static events: EventsHash = {
        'click .rb-c-formatting-toolbar__btn-bold': '_onBoldBtnClick',
        'click .rb-c-formatting-toolbar__btn-code': '_onCodeBtnClick',
        'click .rb-c-formatting-toolbar__btn-italic': '_onItalicBtnClick',
        'click .rb-c-formatting-toolbar__btn-link': '_onLinkBtnClick',
        'click .rb-c-formatting-toolbar__btn-list-ol': '_onOListBtnClick',
        'click .rb-c-formatting-toolbar__btn-list-ul': '_onUListBtnClick',
        'click .rb-c-formatting-toolbar__btn-strikethrough':
            '_onStrikethroughBtnClick',
    };

    /**********************
     * Instance variables *
     **********************/

    /**
     * The CodeMirror instance.
     */
    #codeMirror: CodeMirror;

    /**
     * Initialize the view.
     *
     * Args:
     *     options (FormattingToolbarViewOptions):
     *         Options for the view.
     */
    initialize(options: FormattingToolbarViewOptions) {
        this.#codeMirror = options.editor._codeMirror;
    }

    /**
     * Render the view.
     */
    onInitialRender() {
        this.$el.html(FormattingToolbarView.template);
    }

    /**
     * Handle a click on the "bold" button.
     *
     * Args:
     *     e (JQuery.ClickEvent):
     *         The event object.
     */
    private _onBoldBtnClick(e: JQuery.ClickEvent) {
        e.stopPropagation();
        e.preventDefault();

        this.#toggleInlineTextFormat(['**']);
    }

    /**
     * Handle a click on the "code" button.
     *
     * Args:
     *     e (JQuery.ClickEvent):
     *         The event object.
     */
    private _onCodeBtnClick(e: JQuery.ClickEvent) {
        e.stopPropagation();
        e.preventDefault();

        this.#toggleInlineTextFormat(['`']);
    }

    /**
     * Handle a click on the "italic" button.
     *
     * Args:
     *     e (JQuery.ClickEvent):
     *         The event object.
     */
    private _onItalicBtnClick(e: JQuery.ClickEvent) {
        e.stopPropagation();
        e.preventDefault();

        this.#toggleInlineTextFormat(['_', '*']);
    }

    /**
     * Handle a click on the "link" button.
     *
     * Args:
     *     e (JQuery.ClickEvent):
     *         The event object.
     */
    private _onLinkBtnClick(e: JQuery.ClickEvent) {
        e.stopPropagation();
        e.preventDefault();

        this.#toggleLinkSyntax();
    }

    /**
     * Handle a click on the "ordered list" button.
     *
     * Args:
     *     e (JQuery.ClickEvent):
     *         The event object.
     */
    private _onOListBtnClick(e: JQuery.ClickEvent) {
        e.stopPropagation();
        e.preventDefault();

        this.#toggleListSyntax(true);
    }

    /**
     * Handle a click on the "strikethrough" button.
     *
     * Args:
     *     e (JQuery.ClickEvent):
     *         The event object.
     */
    private _onStrikethroughBtnClick(e: JQuery.ClickEvent) {
        e.stopPropagation();
        e.preventDefault();

        this.#toggleInlineTextFormat(['~~']);
    }

    /**
     * Handle a click on the "unordered list" button.
     *
     * Args:
     *     e (JQuery.ClickEvent):
     *         The event object.
     */
    private _onUListBtnClick(e: JQuery.ClickEvent) {
        e.stopPropagation();
        e.preventDefault();

        this.#toggleListSyntax(false);
    }

    /**
     * Toggle the state of the given inline text format.
     *
     * This toggles the syntax for inline markup such as bold, italic,
     * strikethrough, or code.
     *
     * Args:
     *     symbols (Array of string):
     *         The surrounding markup to add or remove.
     */
    #toggleInlineTextFormat(symbols: string[]) {
        const codeMirror = this.#codeMirror;
        const selection = codeMirror.getSelection();

        if (selection === '') {
            /*
             * If the syntax being toggled does not exist in the group where
             * the cursor is positioned, insert the syntax and position the
             * cursor between the inserted symbols. Otherwise, remove the
             * syntax.
             */
            const [groupStart, groupEnd] = this.#getCurrentTokenGroup();
            const range = codeMirror.getRange(groupStart, groupEnd);

            let wasReplaced = false;

            for (const sym of symbols) {
                if (range.startsWith(sym) && range.endsWith(sym)) {
                    const trimmedRange = this.#removeSyntax(range, sym);
                    codeMirror.replaceRange(trimmedRange, groupStart,
                                            groupEnd);
                    wasReplaced = true;
                    break;
                }
            }

            if (!wasReplaced) {
                const sym = symbols[0];

                codeMirror.replaceRange(`${sym}${range}${sym}`,
                                        groupStart, groupEnd);

                const cursor = codeMirror.getCursor();
                cursor.ch -= sym.length;
                codeMirror.setCursor(cursor);
            }
        } else {
            let wasReplaced = false;

            for (const sym of symbols) {
                if (selection.startsWith(sym) && selection.endsWith(sym)) {
                    /*
                     * The selection starts and ends with syntax matching the
                     * provided symbol, so remove them.
                     *
                     * For example: |**bold text**|
                     */
                    const newSelection = this.#removeSyntax(selection, sym);
                    codeMirror.replaceSelection(newSelection, 'around');
                    wasReplaced = true;
                    break;
                }
            }

            if (!wasReplaced) {
                /*
                 * There is an existing selection that may have syntax outside
                 * of it, so find the beginning and end of the entire token
                 * group, including both word and punctuation characters.
                 *
                 * For example: **|bold text|**
                 */
                const [groupStart, groupEnd] = this.#getCurrentTokenGroup();

                /* Update the selection for replacement. */
                codeMirror.setSelection(groupStart, groupEnd);
                const group = codeMirror.getSelection();

                for (const sym of symbols) {
                    if (group.startsWith(sym) && group.endsWith(sym)) {
                        const newGroup = this.#removeSyntax(group, sym);
                        codeMirror.replaceSelection(newGroup, 'around');
                        wasReplaced = true;
                        break;
                    }
                }

                if (!wasReplaced) {
                    /* The group is not formatted, so add syntax. */
                    const sym = symbols[0];
                    codeMirror.replaceSelection(`${sym}${group}${sym}`,
                                                'around');
                }
            }
        }

        codeMirror.focus();
    }

    /**
     * Return the current token group for the cursor/selection.
     *
     * This will find the surrounding text given the current user's cursor
     * position or selection.
     *
     * Returns:
     *     Array of number:
     *     A 2-element array containing the start and end position of the
     *     current token group.
     */
    #getCurrentTokenGroup(): number[] {
        const codeMirror = this.#codeMirror;
        const cursorStart = codeMirror.getCursor(true);
        const cursorEnd = codeMirror.getCursor(false);

        const groupStart = Object.assign({}, cursorStart);

        for (let curToken = codeMirror.getTokenAt(cursorStart, true);
             curToken.string !== ' ' && groupStart.ch !== 0;
             curToken = codeMirror.getTokenAt(groupStart, true)) {
            groupStart.ch -= 1;
        }

        const line = codeMirror.getLine(cursorStart.line);
        const lineLength = line.length;

        const groupEnd = Object.assign({}, cursorEnd);

        for (let curToken = codeMirror.getTokenAt(cursorEnd, true);
             curToken.string !== ' ' && groupEnd.ch !== lineLength;
             curToken = codeMirror.getTokenAt(groupEnd, true)) {
            groupEnd.ch += 1;
        }

        if (groupEnd.ch !== lineLength) {
            groupEnd.ch -= 1;
        }

        return [groupStart, groupEnd];
    }

    /**
     * Remove the given syntax from the provided text.
     *
     * Args:
     *     text (string):
     *         The text to edit.
     *
     *     sym (string):
     *         The markup to remove from the text.
     *
     * Returns:
     *     string:
     *     The text with the surrounding markup removed.
     */
    #removeSyntax(
        text: string,
        sym: string,
    ): string {
        let escapedSymbol;

        if (sym === '*') {
            escapedSymbol = '\\*';
        } else if (sym === '**') {
            escapedSymbol = '\\*\\*';
        } else {
            escapedSymbol = sym;
        }

        const regex = new RegExp(`^(${escapedSymbol})(.*)\\1$`, 'gm');

        return text.replace(regex, '$2');
    }

    /**
     * Toggle markdown list syntax for the current cursor position.
     *
     * Args:
     *     isOrderedList (boolean):
     *         ``true`` if toggling syntax for an ordered list, ``false`` for
     *         an unordered list.
     */
    #toggleListSyntax(isOrderedList: boolean) {
        const regex = isOrderedList ? /^[0-9]+\.\s/ : /^[\*|\+|-]\s/;
        const listSymbol = isOrderedList ? '1.' : '-';
        const codeMirror = this.#codeMirror;
        const cursor = codeMirror.getCursor();
        const line = codeMirror.getLine(cursor.line);
        const selection = codeMirror.getSelection();

        if (selection === '') {
            /*
             * If the list syntax being toggled exists on the current line,
             * remove it. Otherwise, add the syntax to the current line. In
             * both cases, preserve the relative cursor position if the line is
             * not empty.
             */
            if (regex.test(line)) {
                const newText = line.replace(regex, '');
                codeMirror.replaceRange(
                    newText,
                    { ch: 0, line: cursor.line },
                    { line: cursor.line });

                if (line) {
                    cursor.ch -= listSymbol.length + 1;
                    codeMirror.setCursor(cursor);
                }
            } else {
                codeMirror.replaceRange(
                    `${listSymbol} ${line}`,
                    { ch: 0, line: cursor.line },
                    { line: cursor.line });

                if (line) {
                    cursor.ch += listSymbol.length + 1;
                    codeMirror.setCursor(cursor);
                }
            }
        } else {
            if (regex.test(selection)) {
                const newText = selection.replace(regex, '');
                codeMirror.replaceSelection(newText, 'around');
            } else {
                const cursorStart = codeMirror.getCursor(true);
                const cursorEnd = codeMirror.getCursor(false);
                const precedingText = codeMirror.getLineTokens(cursor.line)
                    .filter(t => t.start < cursorStart.ch)
                    .reduce((acc, token) => acc + token.string, '');

                if (regex.test(precedingText)) {
                    /*
                     * There may be markup before theselection that needs to be
                     * removed, so extend the selection to be replaced if
                     * necessary.
                     */
                    const newText = selection.replace(regex, '');
                    codeMirror.setSelection({ ch: 0, line: cursor.line },
                                            cursorEnd);
                    codeMirror.replaceSelection(newText, 'around');
                } else {
                    /* The selection is not already formatted. Add syntax. */
                    codeMirror.replaceSelection(`${listSymbol} ${selection}`,
                                                'around');
                }
            }
        }

        codeMirror.focus();
    }

    /**
     * Toggle link syntax for the current cursor/selection.
     */
    #toggleLinkSyntax() {
        const regex = /\[(?<text>.*)\]\(.*\)/;
        const codeMirror = this.#codeMirror;
        const selection = codeMirror.getSelection();
        let cursor = codeMirror.getCursor();

        if (selection === '') {
            /*
             * If the group where the cursor is positioned is already a link,
             * remove the syntax. Otherwise, insert the syntax and position the
             * cursor where the text to be displayed will go.
             */
            const [groupStart, groupEnd] = this.#getCurrentTokenGroup();
            const range = codeMirror.getRange(groupStart, groupEnd);

            if (range === '') {
                /*
                 * If the group where the cursor is positioned is empty, insert
                 * the syntax and position the cursor where the text to display
                 * should go.
                 */
                codeMirror.replaceSelection(`[](url)`);
                codeMirror.setCursor(
                    CodeMirror.Pos(cursor.line, cursor.ch + 1));
            } else {
                const match = range.match(regex);

                if (match && match.groups) {
                    /*
                     * If there is a non-empty token group that is a formatted
                     * link, replace the syntax with the text.
                     */
                    const text = match.groups.text;
                    codeMirror.replaceRange(text, groupStart, groupEnd);
                } else {
                    /*
                     * Otherwise, insert the syntax using the token group as
                     * the text to display and position the selection where the
                     * URL will go.
                     */
                    codeMirror.replaceRange(`[${range}](url)`,
                                            groupStart, groupEnd);

                    cursor = codeMirror.getCursor();
                    codeMirror.setSelection(
                        CodeMirror.Pos(cursor.line, cursor.ch - 4),
                        CodeMirror.Pos(cursor.line, cursor.ch - 1));
                }
            }
        } else {
            let match = selection.match(regex);

            if (match && match.groups) {
                /*
                 * If the entire selection matches a formatted link, replace
                 * the selection with the text.
                 */
                codeMirror.replaceSelection(match.groups.text);
            } else {
                /*
                 * The selection may be part of a formatted link, so get the
                 * current token group to test against the regex and remove the
                 * syntax if it matches.
                 */
                const [groupStart, groupEnd] = this.#getCurrentTokenGroup();
                const range = codeMirror.getRange(groupStart, groupEnd);

                match = range.match(regex);

                if (match && match.groups) {
                    codeMirror.replaceRange(match.groups.text,
                                            groupStart, groupEnd);
                } else {
                    /*
                     * The selection is not already formatted, so insert the
                     * syntax using the current selection as the text to
                     * display, and position the selection where the URL will
                     * go.
                     */
                    codeMirror.replaceSelection(`[${selection}](url)`);

                    cursor = codeMirror.getCursor();
                    codeMirror.setSelection(
                        CodeMirror.Pos(cursor.line, cursor.ch - 4),
                        CodeMirror.Pos(cursor.line, cursor.ch - 1));
                }
            }
        }
    }
}


/**
 * Options for the TextEditorView.
 *
 * Version Added:
 *     6.0
 */
export interface TextEditorViewOptions {
    /**
     * Whether the editor should automatically resize to fit its container.
     */
    autoSize?: boolean;

    /**
     * Definitions of a model attribute to use to bind the "richText" value to.
     */
    bindRichText?: {
        attrName: string;
        model: Backbone.Model;
    };

    /**
     * The minimum vertical size of the editor.
     */
    minHeight?: number;

    /**
     * Whether the editor is using rich text (Markdown).
     */
    richText?: boolean;

    /**
     * The initial text.
     */
    text?: string;
}


/**
 * Provides an editor for editing plain or Markdown text.
 *
 * The editor allows for switching between plain or Markdown text on-the-fly.
 *
 * When editing plain text, this uses a standard textarea widget.
 *
 * When editing Markdown, this makes use of CodeMirror. All Markdown content
 * will be formatted as the user types, making it easier to notice when a
 * stray _ or ` will cause Markdown-specific behavior.
 */
@spina
export class TextEditorView extends BaseView<
    Backbone.Model,
    HTMLDivElement,
    TextEditorViewOptions
> {
    static className = 'text-editor';

    static defaultOptions: Partial<TextEditorViewOptions> = {
        autoSize: true,
        minHeight: 70,
    };

    static events: EventsHash ={
        'focus': 'focus',
        'remove': '_onRemove',
    };

    /**********************
     * Instance variables *
     **********************/

    /** The view options. */
    options: TextEditorViewOptions;

    /** Whether the editor is using rich text. */
    richText: boolean;

    /** The markdown formatting toolbar view. */
    #formattingToolbar: FormattingToolbarView = null;

    /** The saved previous height, used to trigger the resize event . */
    #prevClientHeight: number = null;

    /** Whether the rich text state is unsaved. */
    #richTextDirty = false;

    /** The current value of the editor. */
    #value: string;

    /** The editor wrapper. */
    _editor: CodeMirrorWrapper | TextAreaWrapper;

    /**
     * Initialize the view with any provided options.
     *
     * Args:
     *     options (TextEditorViewOptions, optional):
     *         Options for view construction.
     */
    initialize(options: TextEditorViewOptions = {}) {
        this._editor = null;
        this.#prevClientHeight = null;

        this.options = _.defaults(options, TextEditorView.defaultOptions);
        this.richText = !!this.options.richText;
        this.#value = this.options.text || '';
        this.#richTextDirty = false;

        if (this.options.bindRichText) {
            this.bindRichTextAttr(this.options.bindRichText.model,
                                  this.options.bindRichText.attrName);
        }

        /*
         * If the user is defaulting to rich text, we're going to want to
         * show the rich text UI by default, even if any bound rich text
         * flag is set to False.
         *
         * This requires cooperation with the template or API results
         * that end up backing this TextEditor. The expectation is that
         * those will be providing escaped data for any plain text, if
         * the user's set to use rich text by default. If this expectation
         * holds, the user will have a consistent experience for any new
         * text fields.
         */
        if (UserSession.instance.get('defaultUseRichText')) {
            this.setRichText(true);
        }
    }

    /**
     * Render the text editor.
     *
     * This will set the class name on the element, ensuring we have a
     * standard set of styles, even if this editor is bound to an existing
     * element.
     */
    onInitialRender() {
        this.$el.addClass(this.className);
    }

    /**
     * Set whether or not rich text (Markdown) is to be used.
     *
     * This can dynamically change the text editor to work in plain text
     * or Markdown.
     *
     * Args:
     *     richText (boolean):
     *         Whether the editor should use rich text.
     */
    setRichText(richText: boolean) {
        if (richText === this.richText) {
            return;
        }

        if (this._editor) {
            this.hideEditor();
            this.richText = richText;
            this.showEditor();

            this.#richTextDirty = true;

            this.$el.triggerHandler('resize');
        } else {
            this.richText = richText;
        }

        this.trigger('change:richText', richText);
        this.trigger('change');
    }

    /**
     * Bind a richText attribute on a model to the mode on this editor.
     *
     * This editor's richText setting will stay in sync with the attribute
     * on the given mode.
     *
     * Args:
     *     model (Backbone.Model):
     *         A model to bind to.
     *
     *     attrName (string):
     *         The name of the attribute to bind.
     */
    bindRichTextAttr(
        model: Backbone.Model,
        attrName: string,
    ) {
        this.setRichText(model.get(attrName));

        this.listenTo(model, `change:${attrName}`,
                      (model, value) => this.setRichText(value));
    }

    /**
     * Bind an Enable Markdown checkbox to this text editor.
     *
     * The checkbox will initially be set to the value of the editor's
     * richText property. Toggling the checkbox will then manipulate that
     * property.
     *
     * Args:
     *     $checkbox (jQuery):
     *         The checkbox to bind.
     */
    bindRichTextCheckbox($checkbox: JQuery) {
        $checkbox
            .prop('checked', this.richText)
            .on('change', () => this.setRichText($checkbox.prop('checked')));

        this.on('change:richText',
                () => $checkbox.prop('checked', this.richText));
    }

    /**
     * Bind the visibility of an element to the richText property.
     *
     * If richText ist true, the element will be shown. Otherwise, it
     * will be hidden.
     *
     * Args:
     *     $el (jQuery):
     *         The element to show when richText is true.
     */
    bindRichTextVisibility($el: JQuery) {
        $el.toggle(this.richText);

        this.on('change:richText', () => $el.toggle(this.richText));
    }

    /**
     * Return whether or not the editor's contents have changed.
     *
     * Args:
     *     initialValue (string):
     *         The initial value of the editor.
     *
     * Returns:
     *     boolean:
     *     Whether or not the editor is dirty.
     */
    isDirty(
        initialValue: string,
    ): boolean {
        return this._editor !== null &&
               (this.#richTextDirty ||
                this._editor.isDirty(initialValue || ''));
    }

    /**
     * Set the text in the editor.
     *
     * Args:
     *     text (string):
     *         The new text for the editor.
     */
    setText(text: string) {
        if (text !== this.getText()) {
            if (this._editor) {
                this._editor.setText(text);
            } else {
                this.#value = text;
            }
        }

        this.trigger('change');
    }

    /**
     * Return the text in the editor.
     *
     * Returns:
     *     string:
     *     The current contents of the editor.
     */
    getText(): string {
        return this._editor ? this._editor.getText() : this.#value;
    }

    /**
     * Insert a new line of text into the editor.
     *
     * Args:
     *     text (string):
     *         The text to insert.
     */
    insertLine(text: string) {
        if (this._editor) {
            this._editor.insertLine(text);
        } else {
            if (this.#value.endsWith('\n')) {
                this.#value += text + '\n';
            } else {
                this.#value += '\n' + text;
            }
        }

        this.trigger('change');
    }

    /**
     * Set the size of the editor.
     *
     * Args:
     *     width (number):
     *         The new width of the editor.
     *
     *     height (number):
     *         The new height of the editor.
     */
    setSize(
        width: number,
        height: number,
    ) {
        if (this._editor) {
            this._editor.setSize(width, height);
        }
    }

    /**
     * Show the editor.
     *
     * Returns:
     *     TextEditorView:
     *     This object, for chaining.
     */
    show(): this {
        this.$el.show();
        this.showEditor();

        return this;
    }

    /**
     * Hide the editor.
     *
     * Returns:
     *     TextEditorView:
     *     This object, for chaining.
     */
    hide(): this {
        this.hideEditor();
        this.$el.hide();

        return this;
    }

    /**
     * Focus the editor.
     */
    focus() {
        if (this._editor) {
            this._editor.focus();
        }
    }

    /**
     * Handler for the remove event.
     *
     * Disables the drag-and-drop overlay.
     */
    private _onRemove() {
        DnDUploader.instance.unregisterDropTarget(this.$el);
    }

    /**
     * Show the actual editor wrapper.
     *
     * Any stored text will be transferred to the editor, and the editor
     * will take control over all operations.
     */
    showEditor() {
        if (this.richText) {
            DnDUploader.instance.registerDropTarget(
                this.$el, _`Drop to add an image`,
                this._uploadImage.bind(this));

            this._editor = new CodeMirrorWrapper({
                autoSize: this.options.autoSize,
                minHeight: this.options.minHeight,
                parentEl: this.el,
            });

            this.#formattingToolbar = new FormattingToolbarView({
                editor: this._editor,
            });

            $('<div style="height: 3em;">')
                .append(this.#formattingToolbar.render().$el)
                .appendTo(this._editor.$el);
        } else {
            this._editor = new TextAreaWrapper({
                autoSize: this.options.autoSize,
                minHeight: this.options.minHeight,
                parentEl: this.el,
            });
        }

        this._editor.setText(this.#value);
        this.#value = '';
        this.#richTextDirty = false;
        this.#prevClientHeight = null;

        this._editor.$el.on(
            'resize',
            _.throttle(() => this.$el.triggerHandler('resize'), 250));

        this.listenTo(this._editor, 'change', _.throttle(() => {
            /*
             * Make sure that the editor wasn't closed before the throttled
             * handler was reached.
             */
            if (this._editor === null) {
                return;
            }

            const clientHeight = this._editor.getClientHeight();

            if (clientHeight !== this.#prevClientHeight) {
                this.#prevClientHeight = clientHeight;
                this.$el.triggerHandler('resize');
            }

            this.trigger('change');
        }, 500));

        this.focus();
    }

    /**
     * Hide the actual editor wrapper.
     *
     * The last value from the editor will be stored for later retrieval.
     */
    hideEditor() {
        DnDUploader.instance.unregisterDropTarget(this.$el);

        if (this._editor) {
            this.#value = this._editor.getText();
            this.#richTextDirty = false;

            this._editor.remove();
            this._editor = null;

            this.$el.empty();
        }

        if (this.#formattingToolbar) {
            this.#formattingToolbar.remove();
            this.#formattingToolbar = null;
        }
    }

    /**
     * Return whether or not a given file is an image.
     *
     * Args:
     *     file (File):
     *         The file to check.
     *
     * Returns:
     *     boolean:
     *     True if the given file appears to be an image.
     */
    private _isImage(
        file: File,
    ): boolean {
        if (file.type) {
            return (file.type.split('/')[0] === 'image');
        }

        const filename = file.name.toLowerCase();

        return ['.jpeg', '.jpg', '.png', '.gif', '.bmp', '.tiff', '.svg'].some(
            extension => filename.endsWith(extension));
    }

    /**
     * Upload the image and append an image link to the editor's contents.
     *
     * Creates an instance of UserFileAttachment and saves it without the file,
     * then updates the model with the file. This allows the file to be
     * uploaded asynchronously after we get the link that is generated when the
     * UserFileAttachment is created.
     *
     * Args:
     *     file (File):
     *         The image file to upload.
     */
    private _uploadImage(file: File) {
        if (!this._isImage(file)) {
            return;
        }

        const userFileAttachment = new RB.UserFileAttachment({
            caption: file.name,
        });

        userFileAttachment.save()
            .then(() => {
                this.insertLine(
                    `![Image](${userFileAttachment.get('downloadURL')})`);

                userFileAttachment.set('file', file);
                userFileAttachment.save()
                    .catch(err => alert(err.message));
            })
            .catch(err => alert(err.message));
    }
}
