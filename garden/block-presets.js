const gardenBlockPresets=[
 {title:'Открытый доступ ко всем маршрутам',needle:'anyRequest().permitAll()',path:'.kt',severity:'high',fix:'Проверьте политику доступа: требуйте аутентификацию для закрытых маршрутов.',caseSensitive:true},
 {title:'Запуск команд из Kotlin',needle:'Runtime.getRuntime().exec(',path:'.kt',severity:'high',fix:'Проверьте аргументы запуска команды: не передавайте непроверенный пользовательский ввод.',caseSensitive:true},
 {title:'Отладочный режим Spring',needle:'debug=true',path:'.properties',severity:'low',fix:'Отключите отладочный режим в рабочем окружении.',caseSensitive:false},
 {title:'Вывод трассировки стека',needle:'printStackTrace(',path:'.kt',severity:'medium',fix:'Используйте контролируемое журналирование и исключите вывод чувствительных данных.',caseSensitive:true},
 {title:'Разрешённые credentials CORS',needle:'allowCredentials(true)',path:'.kt',severity:'medium',fix:'Проверьте список доверенных origins при разрешённых credentials. Сам вызов не доказывает уязвимость.',caseSensitive:true}
];
if(typeof module!=='undefined')module.exports=gardenBlockPresets;
