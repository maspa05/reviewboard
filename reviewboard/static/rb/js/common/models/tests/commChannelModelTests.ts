import {
    afterEach,
    beforeEach,
    describe,
    expect,
    fail,
    it,
    spyOn,
    suite,
} from 'jasmine-core';

import { ClientCommChannel } from '../commChannelModel';
import { PageView } from '../../views/pageView';


declare const $testsScratch: JQuery;


suite('rb/models/CommChannel', () => {
    let commChannel;

    beforeEach(() => {
        commChannel = new ClientCommChannel();
    });

    afterEach(() => {
        ClientCommChannel.instance = null;
    });

    describe('reload handler', () => {
        let pageView;

        beforeEach(() => {
            const $body = $('<div/>').appendTo($testsScratch);
            const $headerBar = $('<div/>').appendTo($body);
            const $pageContainer = $('<div/>').appendTo($body);
            const $pageContent = $('<div/>').appendTo($pageContainer);
            const $pageSidebar = $('<div/>').appendTo($body);

            pageView = new PageView({
                $body: $body,
                $headerBar: $headerBar,
                $pageContainer: $pageContainer,
                $pageContent: $pageContent,
                $pageSidebar: $pageSidebar,
            });

            spyOn(RB.PageManager, 'getPage')
                .and.returnValue(pageView);
        });

        it('With matching reload data', () => {
            spyOn(pageView, 'getReloadData').and.returnValue({
                test: 1,
            });

            let gotSignal = false;

            commChannel.on('reload', () => {
                gotSignal = true;
            });

            commChannel._onReload({
                data: {
                    test: 1,
                },
                event: 'reload',
            });

            expect(pageView.getReloadData).toHaveBeenCalled();
            expect(gotSignal).toBe(true);
        });

        it('Without matching reload data', () => {
            spyOn(pageView, 'getReloadData').and.returnValue({
                test: 2,
            });

            commChannel.on('reload', () => {
                fail();
            });

            commChannel._onReload({
                data: {
                    test: 1,
                },
                event: 'reload',
            });

            expect(pageView.getReloadData).toHaveBeenCalled();
        });
    });
});
